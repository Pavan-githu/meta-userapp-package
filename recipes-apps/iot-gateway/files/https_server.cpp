#include "https_server.h"
#include "main.h"
#include "user_auth.h"
#include "otp_manager.h"
#include "blockchain_logger.h"

#include <iostream>
#include <gnutls/gnutls.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <sstream>
#include <map>
#include <cstdio>
#include <ctime>

// ---------------------------------------------------------------------------
// Static MFA state
// ---------------------------------------------------------------------------
UserAuth*                          HttpsServer::s_user_auth    = nullptr;
BlockchainLogger*                  HttpsServer::s_blockchain   = nullptr;
std::map<std::string, PendingOTP>         HttpsServer::s_sessions;
std::map<std::string, PasswordFailRecord> HttpsServer::s_pass_fails;
pthread_mutex_t                    HttpsServer::s_session_mutex = PTHREAD_MUTEX_INITIALIZER;
std::vector<std::string>           HttpsServer::s_activity_log;

// Legacy password-only fallback (used when s_user_auth is not set)
std::map<std::string, std::string> HttpsServer::user_db;

// ---------------------------------------------------------------------------
// addActivityLog  –  prepend timestamped entry, keep last 20
// ---------------------------------------------------------------------------
void HttpsServer::addActivityLog(const std::string& entry)
{
    std::time_t now = std::time(nullptr);
    char ts[20];
    std::strftime(ts, sizeof(ts), "%H:%M:%S", std::localtime(&now));
    std::string full = std::string(ts) + "  " + entry;

    pthread_mutex_lock(&s_session_mutex);
    s_activity_log.insert(s_activity_log.begin(), full);
    if (s_activity_log.size() > 20)
        s_activity_log.resize(20);
    pthread_mutex_unlock(&s_session_mutex);
}

// Global buffer for uploaded data
char* uploaded_buffer = nullptr;
size_t uploaded_buffer_size = 0;

// ---------------------------------------------------------------------------
// HttpsServer::initMFA
// ---------------------------------------------------------------------------
void HttpsServer::initMFA(UserAuth* user_auth, BlockchainLogger* blockchain)
{
    s_user_auth  = user_auth;
    s_blockchain = blockchain;
    std::cout << "[HttpsServer] MFA initialized:"
              << " UserAuth=" << (user_auth   ? "yes" : "NO")
              << " Blockchain=" << (blockchain ? "yes" : "NO (audit disabled)")
              << "\n";
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

// Remove expired sessions (called at start of each request handling)
static void purgeExpiredSessions()
{
    std::time_t now = std::time(nullptr);
    pthread_mutex_lock(&HttpsServer::s_session_mutex);
    for (auto it = HttpsServer::s_sessions.begin();
         it != HttpsServer::s_sessions.end(); ) {
        if (it->second.expires_at <= now)
            it = HttpsServer::s_sessions.erase(it);
        else
            ++it;
    }
    pthread_mutex_unlock(&HttpsServer::s_session_mutex);
}

// Read the iotgw_session cookie from the current request
static std::string readSessionCookie(struct MHD_Connection* conn)
{
    const char* val = MHD_lookup_connection_value(
        conn, MHD_COOKIE_KIND, "iotgw_session");
    return val ? std::string(val) : "";
}

// ============================================================================
// Helper: URL-decode a string from application/x-www-form-urlencoded
// ============================================================================
static std::string urlDecode(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '+') {
            result += ' ';
        } else if (str[i] == '%' && i + 2 < str.length()) {
            int hex = 0;
            std::sscanf(str.substr(i + 1, 2).c_str(), "%x", &hex);
            result += static_cast<char>(hex);
            i += 2;
        } else {
            result += str[i];
        }
    }
    return result;
}

// Helper: extract a named field from URL-encoded form body
static std::string getFormField(const std::string& body, const std::string& field) {
    std::string search = field + "=";
    size_t pos = body.find(search);
    if (pos == std::string::npos) return "";
    pos += search.length();
    size_t end = body.find('&', pos);
    std::string value = (end == std::string::npos) ? body.substr(pos) : body.substr(pos, end - pos);
    return urlDecode(value);
}

// Helper: validate password policy
// Requirements: >= 8 chars, >= 1 uppercase, >= 1 lowercase, >= 1 digit, >= 1 special char
static bool validatePassword(const std::string& pwd) {
    if (pwd.length() < 8) return false;
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : pwd) {
        if (std::isupper(static_cast<unsigned char>(c)))  hasUpper   = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower   = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit   = true;
        else if (std::ispunct(static_cast<unsigned char>(c))) hasSpecial = true;
    }
    return hasUpper && hasLower && hasDigit && hasSpecial;
}

// ============================================================================
// UploadData Implementation
// ============================================================================

UploadData::UploadData() : data(nullptr), size(0), capacity(0) {}

UploadData::~UploadData() {
    if (data) {
        delete[] data;
    }
}

void UploadData::append(const char* new_data, size_t new_size) {
    if (size + new_size > capacity) {
        // Resize buffer
        size_t new_capacity = (capacity == 0) ? new_size : capacity * 2;
        while (new_capacity < size + new_size) {
            new_capacity *= 2;
        }
        
        char* new_buffer = new char[new_capacity];
        if (data) {
            std::memcpy(new_buffer, data, size);
            delete[] data;
        }
        data = new_buffer;
        capacity = new_capacity;
    }
    
    std::memcpy(data + size, new_data, new_size);
    size += new_size;
}

// ============================================================================
// ConnectionInfo Implementation
// ============================================================================

ConnectionInfo::ConnectionInfo() : upload_data(nullptr), is_post(false) {}

ConnectionInfo::~ConnectionInfo() {
    if (upload_data) {
        delete upload_data;
    }
}

void ConnectionInfo::createUploadData() {
    if (!upload_data) {
        upload_data = new UploadData();
    }
}

// ============================================================================
// HttpsServer Implementation
// ============================================================================

HttpsServer::HttpsServer(int server_port, const std::string& bind_addr)
    : daemon(nullptr), cert_pem(nullptr), key_pem(nullptr), trust_pem(nullptr),
      port(server_port), running(false), bind_address(bind_addr) {}

HttpsServer::~HttpsServer() {
    stop();
    cleanup();
}

void HttpsServer::cleanup() {
    if (cert_pem) {
        delete[] cert_pem;
        cert_pem = nullptr;
    }
    if (key_pem) {
        delete[] key_pem;
        key_pem = nullptr;
    }
    if (trust_pem) {
        delete[] trust_pem;
        trust_pem = nullptr;
    }
}

// ---------------------------------------------------------------------------
// HttpsServer::loadTrustCA
// Loads the Root CA PEM that the device uses to verify the client certificate
// presented by cloudflared during the TLS handshake (mTLS Level 2).
// ---------------------------------------------------------------------------
bool HttpsServer::loadTrustCA(const char* ca_file) {
    if (!ca_file) return false;
    FILE* fp = fopen(ca_file, "rb");
    if (!fp) {
        std::cerr << "[mTLS] WARNING: Cannot open CA file: " << ca_file
                  << " — client-cert enforcement disabled" << std::endl;
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    trust_pem = new char[sz + 1];
    size_t rd = fread(trust_pem, 1, sz, fp);
    trust_pem[sz] = '\0';
    fclose(fp);
    if (rd != static_cast<size_t>(sz)) {
        std::cerr << "[mTLS] WARNING: Partial CA read — client-cert enforcement disabled" << std::endl;
        delete[] trust_pem;
        trust_pem = nullptr;
        return false;
    }
    std::cout << "[mTLS] Root CA loaded from " << ca_file
              << " — client certificate enforcement ENABLED" << std::endl;
    return true;
}

bool HttpsServer::loadCertificate(const char* cert_file) {
    FILE* cert_fp = fopen(cert_file, "rb");
    if (!cert_fp) {
        std::cerr << "Error: Cannot open certificate file: " << cert_file << std::endl;
        return false;
    }
    
    fseek(cert_fp, 0, SEEK_END);
    long cert_size = ftell(cert_fp);
    fseek(cert_fp, 0, SEEK_SET);
    
    cert_pem = new char[cert_size + 1];
    size_t bytes_read = fread(cert_pem, 1, cert_size, cert_fp);
    cert_pem[cert_size] = '\0';
    fclose(cert_fp);
    
    if (bytes_read != (size_t)cert_size) {
        std::cerr << "Warning: Read " << bytes_read << " bytes, expected " << cert_size << std::endl;
    }
    
    return true;
}

bool HttpsServer::loadKey(const char* key_file) {
    FILE* key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        std::cerr << "Error: Cannot open key file: " << key_file << std::endl;
        return false;
    }
    
    fseek(key_fp, 0, SEEK_END);
    long key_size = ftell(key_fp);
    fseek(key_fp, 0, SEEK_SET);
    
    key_pem = new char[key_size + 1];
    size_t bytes_read = fread(key_pem, 1, key_size, key_fp);
    key_pem[key_size] = '\0';
    fclose(key_fp);
    
    if (bytes_read != (size_t)key_size) {
        std::cerr << "Warning: Read " << bytes_read << " bytes, expected " << key_size << std::endl;
    }
    
    return true;
}

std::string HttpsServer::getLocalIPAddress() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    std::string ip_address = "127.0.0.1";
    
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get network interfaces" << std::endl;
        return ip_address;
    }
    
    // Iterate through network interfaces
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;
        
        std::cout << "Interface: " << ifa->ifa_name << " | Address Family: " << ifa->ifa_addr->sa_family << std::endl;
        // Check for IPv4 address
        if (ifa->ifa_addr->sa_family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                               host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
            
            if (s == 0) {
                std::string temp_ip = host;
                // Skip loopback, prefer eth0 or wlan0
                if (temp_ip != "127.0.0.1" && 
                    (strstr(ifa->ifa_name, "eth") != nullptr || 
                     strstr(ifa->ifa_name, "wlan") != nullptr ||
                     strstr(ifa->ifa_name, "eth0") != nullptr ||
                     strstr(ifa->ifa_name, "eth1") != nullptr ||
                     strstr(ifa->ifa_name, "wlan0") != nullptr ||
                     strstr(ifa->ifa_name, "wlan1") != nullptr ||
                     strstr(ifa->ifa_name, "en") != nullptr)) {
                    //print found IP
                    std::cout << "Selected IP: " << temp_ip << " from interface: " << ifa->ifa_name << std::endl;
                    ip_address = temp_ip;
                    break;
                }
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return ip_address;
}

bool HttpsServer::start(const char* cert_file, const char* key_file,
                        const char* trust_ca_file) {
    if (running) {
        std::cerr << "Server is already running" << std::endl;
        return false;
    }

    // Load server identity certificates
    if (!loadCertificate(cert_file)) {
        std::cerr << "Generate with: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes" << std::endl;
        return false;
    }
    if (!loadKey(key_file)) {
        cleanup();
        return false;
    }

    // Attempt to load Root CA for mTLS client-cert enforcement (Level 2).
    // loadTrustCA() logs a warning and returns false if the file is missing;
    // start() continues without mTLS so development mode still works.
    bool mtls_enabled = loadTrustCA(trust_ca_file);

    // ── Start HTTPS daemon ───────────────────────────────────────────────────
    // When trust_pem is loaded, MHD_OPTION_HTTPS_MEM_TRUST instructs GnuTLS
    // to request a client certificate from the peer (cloudflared) and reject
    // any connection that does not present one signed by the Root CA.
    // This ensures that ONLY the authorised cloudflared instance can reach
    // port 8443 — any direct browser or attacker connection is rejected at
    // the TLS handshake before a single HTTP byte is processed.
    if (mtls_enabled) {
        daemon = MHD_start_daemon(
            MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
            port,
            nullptr, nullptr,
            &HttpsServer::answerToConnection, this,
            MHD_OPTION_HTTPS_MEM_CERT,  cert_pem,
            MHD_OPTION_HTTPS_MEM_KEY,   key_pem,
            MHD_OPTION_HTTPS_MEM_TRUST, trust_pem,   // enforce client cert
            MHD_OPTION_NOTIFY_COMPLETED, HttpsServer::requestCompleted, nullptr,
            MHD_OPTION_END
        );
    } else {
        // mTLS not available — start without client-cert requirement.
        // Suitable for local development; NOT recommended for production.
        std::cerr << "[mTLS] WARNING: Starting without client-cert enforcement."
                     " Direct port-8443 access is not blocked." << std::endl;
        daemon = MHD_start_daemon(
            MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
            port,
            nullptr, nullptr,
            &HttpsServer::answerToConnection, this,
            MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
            MHD_OPTION_HTTPS_MEM_KEY,  key_pem,
            MHD_OPTION_NOTIFY_COMPLETED, HttpsServer::requestCompleted, nullptr,
            MHD_OPTION_END
        );
    }

    if (!daemon) {
        std::cerr << "Failed to start HTTPS server" << std::endl;
        cleanup();
        return false;
    }
    
    running = true;
    
    std::string local_ip = getLocalIPAddress();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "HTTPS Server Started Successfully!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Binding address: " << bind_address << std::endl;
    std::cout << "Port: " << port << std::endl;
    std::cout << "\nAccess URLs:" << std::endl;
    std::cout << "  Local:    https://localhost:" << port << std::endl;
    std::cout << "  Network:  https://" << local_ip << ":" << port << std::endl;
    std::cout << "\nEndpoints:" << std::endl;
    std::cout << "  Upload:   POST https://" << local_ip << ":" << port << "/upload" << std::endl;
    std::cout << "  Web UI:   GET  https://" << local_ip << ":" << port << "/" << std::endl;
    std::cout << "\n⚠️  For PUBLIC internet access:" << std::endl;
    std::cout << "  1. Configure port forwarding on your router" << std::endl;
    std::cout << "  2. Forward external port " << port << " to " << local_ip << ":" << port << std::endl;
    std::cout << "  3. Use your public IP or setup Dynamic DNS" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    return true;
}

void HttpsServer::stop() {
    if (daemon) {
        MHD_stop_daemon(daemon);
        daemon = nullptr;
        running = false;
        std::cout << "Server stopped." << std::endl;
    }
}

// Static callback: Request completed
void HttpsServer::requestCompleted(void* cls, struct MHD_Connection* connection,
                                   void** con_cls, enum MHD_RequestTerminationCode toe) {
    ConnectionInfo* con_info = static_cast<ConnectionInfo*>(*con_cls);
    
    if (con_info) {
        delete con_info;
        *con_cls = nullptr;
    }
}

// Static callback: Iterate POST data
MHD_Result HttpsServer::iteratePost(void* coninfo_cls, enum MHD_ValueKind kind, 
                                    const char* key, const char* filename, 
                                    const char* content_type, const char* transfer_encoding,
                                    const char* data, uint64_t off, size_t size) {
    ConnectionInfo* con_info = static_cast<ConnectionInfo*>(coninfo_cls);
    
    if (size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(data, size);
        std::cout << "Received chunk: " << size << " bytes (offset: " << off << ")" << std::endl;
    }
    
    return MHD_YES;
}

// Handle POST upload request
MHD_Result HttpsServer::handlePostUpload(struct MHD_Connection* connection, 
                                         ConnectionInfo* con_info,
                                         const char* upload_data, 
                                         size_t* upload_data_size) {
    if (*upload_data_size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(upload_data, *upload_data_size);
        std::cout << "Received POST data chunk: " << *upload_data_size << " bytes" << std::endl;
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        // Upload complete
        std::string response_str;
        UploadData* upload = con_info->getUploadData();
        
        if (upload && upload->getSize() > 0) {
            response_str = "Upload successful! Received " + 
                          std::to_string(upload->getSize()) + " bytes\n";
            
            std::cout << "Total upload size: " << upload->getSize() << " bytes" << std::endl;
            std::cout << "Data stored at memory address: " 
                     << static_cast<void*>(upload->getData()) << std::endl;
            
            // Free previous global buffer if exists
            if (uploaded_buffer != nullptr) {
                delete[] uploaded_buffer;
                uploaded_buffer = nullptr;
            }
            
            // Store uploaded data in global buffer
            uploaded_buffer_size = upload->getSize();
            uploaded_buffer = new char[uploaded_buffer_size];
            std::memcpy(uploaded_buffer, upload->getData(), uploaded_buffer_size);
            
            std::cout << "Data copied to global buffer (size: " << uploaded_buffer_size << " bytes)" << std::endl;
            // Global buffer persists and can be accessed by other functions
        } else {
            response_str = "No data received\n";
        }
        
        return sendResponse(connection, response_str, MHD_HTTP_OK);
    }
}

// Forward declarations for helpers defined later in this file
static std::string buildBlockchainErrorPage(const std::string& reason, const std::string& backUrl);
static std::string blockchainStatusBanner(bool statusOk, const std::string& detail);

// Handle GET request
MHD_Result HttpsServer::handleGetRequest(struct MHD_Connection* connection, const char* url) {

    // --- System status page ---
    if (std::strcmp(url, "/status") == 0) {
        std::string bc_status;
        bool bc_ok = false;
        if (s_blockchain) {
            std::string bc_err;
            bc_ok = s_blockchain->checkConnectivity(bc_err);
            bc_status = bc_ok ? s_blockchain->getStatusString() : bc_err;
        } else {
            bc_status = "Blockchain logger not initialised.";
        }

        const char* bc_color = bc_ok ? "green"  : "red";
        const char* bc_icon  = bc_ok ? "&#9989;" : "&#10060;";

        // Build activity log rows
        std::string log_rows;
        pthread_mutex_lock(&s_session_mutex);
        std::vector<std::string> log_copy = s_activity_log;
        pthread_mutex_unlock(&s_session_mutex);

        if (log_copy.empty()) {
            log_rows = "<tr><td colspan='2' style='color:#aaa;text-align:center;'>No activity yet</td></tr>";
        } else {
            for (const auto& entry : log_copy) {
                // Split "HH:MM:SS  message" for two-column display
                auto sp = entry.find("  ");
                std::string t = (sp != std::string::npos) ? entry.substr(0, sp) : "";
                std::string m = (sp != std::string::npos) ? entry.substr(sp+2) : entry;
                // Pick row color by event type
                std::string color = "#333";
                if (m.find("FAIL") != std::string::npos || m.find("LOCKOUT") != std::string::npos)
                    color = "#c0392b";
                else if (m.find("SUCCESS") || m.find("granted") != std::string::npos)
                    color = "#27ae60";
                else if (m.find("BLOCKCHAIN") != std::string::npos)
                    color = "#2980b9";
                log_rows +=
                    "<tr><td style='color:#888;white-space:nowrap;padding:4px 8px;'>" + t + "</td>"
                    "<td style='color:" + color + ";padding:4px 8px;'>" + m + "</td></tr>";
            }
        }

        std::string page =
            "<!DOCTYPE html><html lang=\"en\">"
            "<head><meta charset=\"UTF-8\"><title>System Status</title>"
            "<style>body{font-family:Arial,sans-serif;padding:24px;max-width:700px;margin:auto;}"
            ".row{display:flex;justify-content:space-between;align-items:center;"
            "border-bottom:1px solid #eee;padding:12px 0;}"
            ".label{font-weight:bold;color:#333;}"
            ".val{color:" + std::string(bc_color) + ";}"
            "h1{color:#2c3e50;}h2{color:#34495e;margin-top:28px;}"
            ".detail{font-size:0.82em;color:#777;word-break:break-all;}"
            "table{width:100%;border-collapse:collapse;font-size:0.88em;}"
            "th{text-align:left;padding:6px 8px;background:#f0f4f8;color:#555;}"
            "tr:nth-child(even){background:#fafafa;}</style>"
            "<meta http-equiv=\"refresh\" content=\"15\"/>"
            "</head><body>"
            "<h1>IoT Gateway System Status</h1>"
            "<div class=\"row\">"
            "  <span class=\"label\">HTTPS Server</span>"
            "  <span style=\"color:green;\">&#9989; Running</span>"
            "</div>"
            "<div class=\"row\">"
            "  <span class=\"label\">Ethereum Node</span>"
            "  <span class=\"val\">" + bc_icon + " " + (bc_ok ? "Reachable" : "Unreachable") + "</span>"
            "</div>"
            "<div class=\"row\"><span class=\"detail\">" + bc_status + "</span></div>"
            "<h2>Blockchain Activity Log</h2>"
            "<table>"
            "<tr><th>Time</th><th>Event</th></tr>"
            + log_rows +
            "</table>"
            "<p style=\"color:#888;font-size:0.8em;margin-top:16px;\">Page auto-refreshes every 15 seconds. "
            "<a href=\"/status\">Refresh now</a></p>"
            "<p><a href=\"/\">&#8592; Home</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_OK);
    }

    // --- Registration page ---
    if (std::strcmp(url, "/register") == 0) {
        std::string page =
            "<html><body>"
            "<h1>Register</h1>"
            "<form action=\"/register\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Register\"/>"
            "</form>"
            "<p><a href=\"/login\">Already registered? Log in</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_OK);
    }

    // --- Login page ---
    if (std::strcmp(url, "/login") == 0) {
        // Show live blockchain status banner in the login form
        std::string bc_banner;
        if (s_blockchain) {
            std::string bc_err;
            bool bc_ok = s_blockchain->checkConnectivity(bc_err);
            std::string detail = bc_ok ? s_blockchain->getStatusString() : bc_err;
            bc_banner = blockchainStatusBanner(bc_ok, detail);
        } else {
            bc_banner = blockchainStatusBanner(false, "Blockchain logger not initialised.");
        }

        std::string page =
            "<html><body>"
            "<h1>Login</h1>"
            + bc_banner +
            "<form action=\"/login\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Login\"/>"
            "</form>"
            "<p><a href=\"/register\">Don&apos;t have an account? Register</a></p>"
            "<p><small><a href=\"/status\">System Status</a></small></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_OK);
    }

    // --- OTP page ---
    if (std::strcmp(url, "/otp") == 0) {
        std::string page =
            "<html><head><title>OTP Verification</title>"
            "<script>"
            "var seconds = 120;"
            "function countdown() {"
            "  var m = Math.floor(seconds / 60);"
            "  var s = seconds % 60;"
            "  document.getElementById('timer').innerText = "
            "    (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;"
            "  if (seconds <= 0) {"
            "    document.getElementById('otp-form').style.display = 'none';"
            "    document.getElementById('expired').style.display = 'block';"
            "  } else { seconds--; setTimeout(countdown, 1000); }"
            "}"
            "window.onload = countdown;"
            "</script></head><body>"
            "<h1>OTP Verification</h1>"
            "<p>Enter the 6-digit OTP sent to you.</p>"
            "<p>Time remaining: <strong id='timer'>02:00</strong></p>"
            "<div id='otp-form'>"
            "<form action='/otp' method='post'>"
            "<label>OTP: <input type='text' name='otp' maxlength='6' "
            "pattern='[0-9]{6}' placeholder='000000' required "
            "style='font-size:1.5em; letter-spacing:0.3em; width:8em;'/></label><br/><br/>"
            "<input type='submit' value='Verify OTP'/>"
            "</form>"
            "</div>"
            "<div id='expired' style='display:none; color:red;'>"
            "<p>OTP has expired. Please <a href='/login'>log in again</a>.</p>"
            "</div>"
            "<p><a href='/login'>Back to Login</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_OK);
    }

    // --- Landing page (default) ---
    std::string page =
        "<html><body>"
        "<h1>RaceIoT Device</h1>"
        "<p>Welcome! Please register or log in to continue.</p>"
        "<a href=\"/register\"><button>Register</button></a>&nbsp;&nbsp;"
        "<a href=\"/login\"><button>Login</button></a>"
        "<hr/>"
        "<h2>HTTPS Upload Server</h2>"
        "<p>POST data to /upload endpoint</p>"
        "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">"
        "<input type=\"file\" name=\"file\"/>"
        "<input type=\"submit\" value=\"Upload\"/>"
        "</form>"
        "</body></html>";

    return sendResponse(connection, page, MHD_HTTP_OK);
}

// ============================================================================
// Blockchain error page helper
// ============================================================================

/**
 * Returns a styled HTML page that informs the user the blockchain is
 * unreachable.  Used in all three POST handlers (register/login/otp).
 *
 * @param reason  Human-readable reason string from checkConnectivity().
 * @param backUrl URL for the "Try Again" / back button (e.g. "/login").
 */
static std::string buildBlockchainErrorPage(const std::string& reason,
                                             const std::string& backUrl)
{
    return
        "<!DOCTYPE html><html lang=\"en\">"
        "<head><meta charset=\"UTF-8\"><title>Blockchain Unavailable</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;margin:0;padding:0;"
        "background:#f5f5f5;display:flex;justify-content:center;align-items:center;"
        "min-height:100vh;}"
        ".card{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.15);"
        "padding:36px 40px;max-width:520px;width:100%;}"
        ".icon{font-size:3em;text-align:center;margin-bottom:8px;}"
        "h1{color:#c0392b;margin-top:0;font-size:1.4em;text-align:center;}"
        ".reason{background:#fdf3f2;border-left:4px solid #c0392b;"
        "padding:10px 14px;border-radius:4px;font-size:0.85em;"
        "color:#555;word-break:break-all;margin:16px 0;}"
        ".btn{display:inline-block;margin-top:18px;padding:10px 24px;"
        "background:#3498db;color:#fff;text-decoration:none;"
        "border-radius:5px;font-size:1em;}"
        ".btn:hover{background:#2980b9;}"
        "p{color:#444;line-height:1.5;}"
        "</style></head>"
        "<body><div class=\"card\">"
        "<div class=\"icon\">&#128274;</div>"
        "<h1>Blockchain Not Accessible</h1>"
        "<p>Authentication requires a live connection to the Ethereum audit ledger "
        "on the IoT Gateway VPS. The node is currently unreachable.</p>"
        "<p><strong>What this means:</strong> Your credentials cannot be verified "
        "without a blockchain connection. No access is granted.</p>"
        "<div class=\"reason\"><strong>Technical detail:</strong> " + reason + "</div>"
        "<p>Please contact the system administrator or try again once the "
        "Ethereum node is back online.</p>"
        "<a href=\"" + backUrl + "\" class=\"btn\">&#8592; Try Again</a>"
        "</div></body></html>";
}

/**
 * Returns a small HTML warning banner to embed in other pages when blockchain
 * is reachable but might be degraded.  Pass statusOk=true for a green banner,
 * false for a yellow warning.
 */
static std::string blockchainStatusBanner(bool statusOk, const std::string& detail)
{
    const char* bg  = statusOk ? "#d4edda" : "#fff3cd";
    const char* col = statusOk ? "#155724" : "#856404";
    const char* ico = statusOk ? "&#9989;" : "&#9888;";
    return
        "<div style=\"background:" + std::string(bg) + ";color:" + col + ";"
        "border-radius:5px;padding:8px 14px;margin-bottom:14px;"
        "font-size:0.85em;\">"
        + ico + " <strong>Blockchain:</strong> " + detail +
        "</div>";
}

// Handle POST /register
MHD_Result HttpsServer::handleRegisterPost(struct MHD_Connection* connection,
                                            ConnectionInfo* con_info,
                                            const char* upload_data,
                                            size_t* upload_data_size) {
    if (*upload_data_size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    // ── Live blockchain status (non-blocking: registration is local, warn only)
    std::string bc_status_detail;
    bool bc_ok = false;
    if (s_blockchain) {
        std::string bc_err;
        bc_ok = s_blockchain->checkConnectivity(bc_err);
        bc_status_detail = bc_ok ? s_blockchain->getStatusString() : bc_err;
    } else {
        bc_status_detail = "Blockchain logger not initialised.";
    }

    // Parse form body
    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";

    std::string username = getFormField(body_str, "username");
    std::string password = getFormField(body_str, "password");

    std::string page;
    if (username.empty() || password.empty()) {
        page =
            "<html><body>"
            "<h1>Register</h1>"
            "<p style=\"color:red;\">Username and password are required.</p>"
            "<form action=\"/register\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Register\"/>"
            "</form>"
            "<p><a href=\"/login\">Already registered? Log in</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_BAD_REQUEST);
    }

    // Password policy check
    if (!validatePassword(password)) {
        page =
            "<html><body>"
            "<h1>Register</h1>"
            "<p style=\"color:red;\">Password does not match policy:<br/>"
            "&bull; Minimum 8 characters<br/>"
            "&bull; At least one uppercase letter<br/>"
            "&bull; At least one lowercase letter<br/>"
            "&bull; At least one digit<br/>"
            "&bull; At least one special character (!@#$%^&amp;* etc.)</p>"
            "<form action=\"/register\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" value=\"" + username + "\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Register\"/>"
            "</form>"
            "<p><a href=\"/login\">Already registered? Log in</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_BAD_REQUEST);
    }

    // ── Use UserAuth (PBKDF2) if available, else legacy user_db ────────────
    bool registered = false;
    std::string totp_uri;

    if (s_user_auth) {
        registered = s_user_auth->registerUser(username, password);
        if (registered) {
            // Retrieve the generated TOTP secret to build the QR URI
            std::string totp_secret;
            s_user_auth->getTotpSecret(username, totp_secret);
            totp_uri = OTPManager::buildOtpauthURI("RaceIoT-Gateway", username, totp_secret);
        }
    } else {
        // Legacy fallback
        if (user_db.find(username) == user_db.end()) {
            user_db[username] = password;
            registered = true;
        }
    }

    if (!registered) {
        page =
            "<html><body>"
            "<h1>Register</h1>"
            "<p style=\"color:red;\">Username already exists or registration failed.</p>"
            "<form action=\"/register\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" value=\"" + username + "\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Register\"/>"
            "</form>"
            "<p><a href=\"/login\">Already registered? Log in</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_CONFLICT);
    }

    std::cout << "[Register] New user registered: " << username << "\n";
    addActivityLog("[REGISTER] User '" + username + "' registered successfully");
    if (bc_ok)
        addActivityLog("[BLOCKCHAIN] Seed commitment submitted for '" + username + "'");
    else
        addActivityLog("[BLOCKCHAIN] Node unreachable — seed not committed for '" + username + "'");

    // ── Success: show the TOTP QR code setup instructions ──────────────────
    page =
        "<html><head><title>Registration Successful</title></head><body>"
        "<h1>Registration Successful!</h1>"
        "<p>Welcome, <strong>" + username + "</strong>!</p>"
        "<hr/>"
        "<h2>Set Up Two-Factor Authentication (TOTP)</h2>"
        "<p>You <strong>must</strong> complete this step before you can log in.</p>"
        "<ol>"
        "<li>Install <strong>Google Authenticator</strong>, <strong>Authy</strong>, or any TOTP app.</li>"
        "<li>In the app, tap <em>Add account → Scan QR code</em>.</li>"
        "<li>Scan the QR code below, or enter the URI manually.</li>"
        "</ol>";

    if (!totp_uri.empty()) {
        // Embed a QR code via the free qrserver.com API (replace with a local
        // generator in fully air-gapped deployments).
        std::string qr_url = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=";
        // Minimal percent-encoding of the otpauth URI for the img src
        std::string encoded_uri;
        for (unsigned char c : totp_uri) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~'
                || c == ':' || c == '/' || c == '?' || c == '=' || c == '&') {
                encoded_uri += c;
            } else {
                char buf[4]; std::snprintf(buf, sizeof(buf), "%%%02X", c);
                encoded_uri += buf;
            }
        }
        page += "<p><img src=\"" + qr_url + encoded_uri + "\" alt=\"TOTP QR Code\" width=\"200\" height=\"200\"/></p>";
        page += "<p><small>URI: <code>" + totp_uri + "</code></small></p>";
    }

    page +=
        "<hr/>"
        + blockchainStatusBanner(bc_ok, bc_status_detail) +
        (bc_ok ? "" :
            "<p style=\"color:#856404;\"><strong>Note:</strong> The seed commitment "
            "could not be recorded on the blockchain. Login will still use TOTP, "
            "but blockchain audit logging is currently unavailable.</p>")
        +
        "<p>Once you have added the account to your authenticator app, "
        "<a href=\"/login\"><button>Log In</button></a></p>"
        "</body></html>";

    return sendResponse(connection, page, MHD_HTTP_OK);
}

// Handle POST /login
MHD_Result HttpsServer::handleLoginPost(struct MHD_Connection* connection,
                                         ConnectionInfo* con_info,
                                         const char* upload_data,
                                         size_t* upload_data_size) {
    if (*upload_data_size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    // ── Live blockchain connectivity check (blocking: login requires chain) ──
    {
        std::string bc_err;
        bool bc_ok = s_blockchain && s_blockchain->checkConnectivity(bc_err);
        if (!bc_ok) {
            if (bc_err.empty()) bc_err = "Blockchain logger not initialised.";
            std::cerr << "[Login] Blockchain unreachable: " << bc_err << "\n";
            return sendResponse(connection,
                buildBlockchainErrorPage(bc_err, "/login"),
                MHD_HTTP_SERVICE_UNAVAILABLE);
        }
    }

    purgeExpiredSessions();

    // Parse form body
    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";

    std::string username = getFormField(body_str, "username");
    std::string password = getFormField(body_str, "password");

    // ── Input validation — reject before touching the database ───────────────
    // isValidUsername enforces: non-empty, ≤64 chars, [a-zA-Z0-9_-] only.
    // Checked HERE so no DB I/O occurs on malformed input.
    if (username.empty() || password.empty() ||
        !UserAuth::isValidUsername(username)) {
        return sendResponse(connection,
            "<html><body><h1>Login</h1>"
            "<p style='color:red;'>Invalid username or password.</p>"
            "<form action='/login' method='post'>"
            "<label>Username: <input type='text' name='username' required/></label><br/><br/>"
            "<label>Password: <input type='password' name='password' required/></label><br/><br/>"
            "<input type='submit' value='Login'/>"
            "</form></body></html>",
            MHD_HTTP_BAD_REQUEST);
    }

    // ── Check password lockout (local, first factor) ─────────────────────────
    {
        pthread_mutex_lock(&s_session_mutex);
        auto pf = s_pass_fails.find(username);
        if (pf != s_pass_fails.end() && pf->second.locked) {
            pthread_mutex_unlock(&s_session_mutex);
            addActivityLog("[LOGIN] Account locked (password) for '" + username + "'");
            return sendResponse(connection,
                "<html><body><h1>Account Locked</h1>"
                "<p>Too many failed password attempts. Contact an administrator.</p>"
                "<p><a href='/login'>Back to Login</a></p>"
                "</body></html>",
                MHD_HTTP_FORBIDDEN);
        }
        pthread_mutex_unlock(&s_session_mutex);
    }

    // ── Verify password ─────────────────────────────────────────────────────
    bool auth_ok = false;
    if (s_user_auth) {
        auth_ok = s_user_auth->authenticate(username, password);
    } else {
        // Legacy fallback
        auto it = user_db.find(username);
        auth_ok = (it != user_db.end() && it->second == password);
    }

    // Log to blockchain regardless of outcome
    std::string sid_for_log = BlockchainLogger::generateSessionId();
    if (s_blockchain) {
        s_blockchain->logEvent(username,
            auth_ok ? BlockchainLogger::LOGIN_ATTEMPT
                    : BlockchainLogger::LOGIN_FAIL,
            sid_for_log);
        addActivityLog(auth_ok
            ? "[BLOCKCHAIN] Login attempt logged for '" + username + "' (tx submitted)"
            : "[BLOCKCHAIN] Failed login logged for '" + username + "'");
    }
    addActivityLog(auth_ok
        ? "[LOGIN] Password OK for '" + username + "' — OTP phase starting"
        : "[LOGIN] FAILED password for '" + username + "'");

    if (!auth_ok) {
        // Increment password fail counter
        pthread_mutex_lock(&s_session_mutex);
        auto& rec = s_pass_fails[username];
        rec.count++;
        if (rec.count >= MAX_PASSWORD_FAILS)
            rec.locked = true;
        int pw_remaining = MAX_PASSWORD_FAILS - rec.count;
        pthread_mutex_unlock(&s_session_mutex);

        std::cerr << "[Login] Failed password attempt for user: " << username
                  << " (" << rec.count << "/" << MAX_PASSWORD_FAILS << ")\n";
        addActivityLog("[LOGIN] FAILED password for '" + username + "' ("
            + std::to_string(rec.count) + "/" + std::to_string(MAX_PASSWORD_FAILS) + ")");

        if (pw_remaining <= 0) {
            return sendResponse(connection,
                "<html><body><h1>Account Locked</h1>"
                "<p>Too many failed password attempts. Contact an administrator.</p>"
                "<p><a href='/login'>Back to Login</a></p>"
                "</body></html>",
                MHD_HTTP_FORBIDDEN);
        }

        std::string page =
            "<html><body>"
            "<h1>Login</h1>"
            "<p style=\"color:red;\">Invalid username or password. "
            + std::to_string(pw_remaining) + " attempt(s) remaining.</p>"
            "<form action=\"/login\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Login\"/>"
            "</form>"
            "<p><a href=\"/register\">Don&apos;t have an account? Register</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_UNAUTHORIZED);
    }

    // ── Password OK: reset fail counter ─────────────────────────────────────
    pthread_mutex_lock(&s_session_mutex);
    s_pass_fails.erase(username);
    pthread_mutex_unlock(&s_session_mutex);

    // ── Password OK: check if TOTP is provisioned ────────────────────────────
    std::string totp_secret;
    bool has_totp = false;
    if (s_user_auth) {
        has_totp = s_user_auth->getTotpSecret(username, totp_secret);
    }

    if (!has_totp) {
        // No TOTP secret: legacy path – grant session directly (no MFA)
        std::cout << "[Login] User '" << username << "' has no TOTP – granting session (no MFA)\n";
        std::string page =
            "<html><body><h1>Login Successful (No MFA)</h1>"
            "<p>Welcome back, <strong>" + username + "</strong>.</p>"
            "<p style=\"color:orange;\">No TOTP key configured. Please re-register to enable MFA.</p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_OK);
    }

    // ── Create OTP session ───────────────────────────────────────────────────
    std::string session_id = BlockchainLogger::generateSessionId();
    if (session_id.empty()) {
        std::cerr << "[Login] Failed to generate session ID\n";
        return sendResponse(connection, "<html><body><p>Internal error.</p></body></html>",
                            MHD_HTTP_INTERNAL_SERVER_ERROR);
    }

    PendingOTP pending;
    pending.username    = username;
    pending.totp_secret = totp_secret;
    pending.session_id  = session_id;
    pending.expires_at  = std::time(nullptr) + OTP_SESSION_TTL;
    pending.local_fails = 0;

    pthread_mutex_lock(&s_session_mutex);
    s_sessions[session_id] = pending;
    pthread_mutex_unlock(&s_session_mutex);

    // Log OTP_SENT to blockchain (session_id links all events in this attempt)
    if (s_blockchain) {
        s_blockchain->logEvent(username, BlockchainLogger::OTP_SENT, session_id);
        addActivityLog("[BLOCKCHAIN] OTP_SENT logged for '" + username + "' session=" + session_id.substr(0,8) + "...");
    }

    std::cout << "[Login] Password OK for '" << username << "' – OTP phase started\n";

    // ── Build redirect response with session cookie ──────────────────────────
    std::string body_html =
        "<html><head>"
        "<meta http-equiv=\"refresh\" content=\"0;url=/otp\"/>"
        "</head><body>"
        "<p>Redirecting to OTP verification...</p>"
        "</body></html>";

    struct MHD_Response* resp = MHD_create_response_from_buffer(
        body_html.size(),
        const_cast<char*>(body_html.c_str()),
        MHD_RESPMEM_MUST_COPY);

    // Set Secure HttpOnly SameSite=Strict cookie for the OTP session
    std::string cookie = "iotgw_session=" + session_id +
                         "; HttpOnly; Secure; SameSite=Strict; Path=/otp; Max-Age=120";
    MHD_add_response_header(resp, "Set-Cookie", cookie.c_str());
    MHD_add_response_header(resp, "Content-Type", "text/html");

    MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_SEE_OTHER, resp);
    MHD_destroy_response(resp);
    return ret;
}

// Handle POST /otp
MHD_Result HttpsServer::handleOtpPost(struct MHD_Connection* connection,
                                       ConnectionInfo* con_info,
                                       const char* upload_data,
                                       size_t* upload_data_size) {
    if (*upload_data_size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    // ── Live blockchain connectivity check (blocking: reveal() requires chain)
    {
        std::string bc_err;
        bool bc_ok = s_blockchain && s_blockchain->checkConnectivity(bc_err);
        if (!bc_ok) {
            if (bc_err.empty()) bc_err = "Blockchain logger not initialised.";
            std::cerr << "[OTP] Blockchain unreachable: " << bc_err << "\n";
            return sendResponse(connection,
                buildBlockchainErrorPage(bc_err, "/login"),
                MHD_HTTP_SERVICE_UNAVAILABLE);
        }
    }

    purgeExpiredSessions();

    // ── Read session cookie ──────────────────────────────────────────────────
    std::string session_id = readSessionCookie(connection);
    if (session_id.empty()) {
        return sendResponse(connection,
            "<html><body><h1>Session Error</h1>"
            "<p>No session found. Please <a href='/login'>log in again</a>.</p>"
            "</body></html>", MHD_HTTP_UNAUTHORIZED);
    }

    // ── Look up pending OTP session ──────────────────────────────────────────
    pthread_mutex_lock(&s_session_mutex);
    auto sit = s_sessions.find(session_id);
    if (sit == s_sessions.end()) {
        pthread_mutex_unlock(&s_session_mutex);
        return sendResponse(connection,
            "<html><body><h1>Session Expired</h1>"
            "<p>Your OTP session has expired. Please <a href='/login'>log in again</a>.</p>"
            "</body></html>", MHD_HTTP_UNAUTHORIZED);
    }
    PendingOTP pending = sit->second;  // copy under lock
    pthread_mutex_unlock(&s_session_mutex);

    // Check wall-clock expiry
    if (std::time(nullptr) > pending.expires_at) {
        pthread_mutex_lock(&s_session_mutex);
        s_sessions.erase(session_id);
        pthread_mutex_unlock(&s_session_mutex);
        return sendResponse(connection,
            "<html><body><h1>OTP Expired</h1>"
            "<p>The OTP window has expired. Please <a href='/login'>log in again</a>.</p>"
            "</body></html>", MHD_HTTP_UNAUTHORIZED);
    }

    // ── Local fail-count fast-path lockout ───────────────────────────────────
    if (pending.local_fails >= MAX_LOCAL_OTP_FAILS) {
        pthread_mutex_lock(&s_session_mutex);
        s_sessions.erase(session_id);
        pthread_mutex_unlock(&s_session_mutex);
        return sendResponse(connection,
            "<html><body><h1>Account Locked</h1>"
            "<p>Too many failed OTP attempts. Contact an administrator.</p>"
            "</body></html>", MHD_HTTP_FORBIDDEN);
    }

    // ── Query blockchain lockout (authoritative) ─────────────────────────────
    if (s_blockchain && s_blockchain->isUserLocked(pending.username)) {
        pthread_mutex_lock(&s_session_mutex);
        s_sessions.erase(session_id);
        pthread_mutex_unlock(&s_session_mutex);
        std::cerr << "[OTP] User '" << pending.username << "' is locked on-chain\n";
        return sendResponse(connection,
            "<html><body><h1>Account Locked</h1>"
            "<p>Your account is locked on the blockchain. Contact an administrator to unlock.</p>"
            "</body></html>", MHD_HTTP_FORBIDDEN);
    }

    // ── Parse OTP from form body ─────────────────────────────────────────────
    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";
    std::string otp = getFormField(body_str, "otp");

    // Structural validation
    bool fmt_ok = (otp.size() == 6);
    for (char c : otp) if (!std::isdigit(static_cast<unsigned char>(c))) { fmt_ok = false; break; }

    if (!fmt_ok) {
        std::string page =
            "<html><body><h1>OTP Verification</h1>"
            "<p style='color:red;'>Invalid OTP format. Enter exactly 6 digits.</p>"
            "<form action='/otp' method='post'>"
            "<label>OTP: <input type='text' name='otp' maxlength='6' pattern='[0-9]{6}' "
            "placeholder='000000' required style='font-size:1.5em;letter-spacing:0.3em;width:8em;'/>"
            "</label><br/><br/>"
            "<input type='submit' value='Verify OTP'/>"
            "</form>"
            "<p><a href='/login'>Back to Login</a></p></body></html>";
        return sendResponse(connection, page, MHD_HTTP_BAD_REQUEST);
    }

    // ── Verify TOTP (constant-time via OTPManager) ───────────────────────────
    bool otp_ok = OTPManager::verifyTOTP(pending.totp_secret, otp);

    if (!otp_ok) {
        // Increment local fail count
        pthread_mutex_lock(&s_session_mutex);
        auto it2 = s_sessions.find(session_id);
        if (it2 != s_sessions.end()) {
            it2->second.local_fails++;
            pending.local_fails = it2->second.local_fails;
        }
        pthread_mutex_unlock(&s_session_mutex);

        // Log OTP_FAIL to blockchain
        if (s_blockchain) {
            s_blockchain->logEvent(pending.username, BlockchainLogger::OTP_FAIL, session_id);
            addActivityLog("[BLOCKCHAIN] OTP_FAIL logged for '" + pending.username + "'");
            // If local fails now >= max, also log LOCKOUT event
            if (pending.local_fails >= MAX_LOCAL_OTP_FAILS) {
                s_blockchain->logEvent(pending.username, BlockchainLogger::LOCKOUT, session_id);
                addActivityLog("[BLOCKCHAIN] LOCKOUT logged for '" + pending.username + "'");
            }
        }
        addActivityLog("[OTP] Wrong code for '" + pending.username + "' ("
            + std::to_string(pending.local_fails) + "/" + std::to_string(MAX_LOCAL_OTP_FAILS) + " fails)");

        std::cerr << "[OTP] Wrong OTP for '" << pending.username
                  << "' (local fail " << pending.local_fails << "/" << MAX_LOCAL_OTP_FAILS << ")\n";

        int remaining = MAX_LOCAL_OTP_FAILS - pending.local_fails;
        std::string page =
            "<html><body><h1>OTP Verification</h1>"
            "<p style='color:red;'>Incorrect OTP. " +
            std::to_string(remaining) + " attempt(s) remaining.</p>"
            "<form action='/otp' method='post'>"
            "<label>OTP: <input type='text' name='otp' maxlength='6' pattern='[0-9]{6}' "
            "placeholder='000000' required style='font-size:1.5em;letter-spacing:0.3em;width:8em;'/>"
            "</label><br/><br/>"
            "<input type='submit' value='Verify OTP'/>"
            "</form>"
            "<p><a href='/login'>Back to Login</a></p></body></html>";
        return sendResponse(connection, page, MHD_HTTP_UNAUTHORIZED);
    }

    // ── OTP correct: log success and grant session ───────────────────────────
    if (s_blockchain) {
        s_blockchain->logEvent(pending.username, BlockchainLogger::OTP_SUCCESS, session_id);
        addActivityLog("[BLOCKCHAIN] OTP_SUCCESS logged for '" + pending.username + "' — access granted");
    }
    addActivityLog("[OTP] Verified successfully for '" + pending.username + "'");

    // Remove the one-time OTP session
    pthread_mutex_lock(&s_session_mutex);
    s_sessions.erase(session_id);
    pthread_mutex_unlock(&s_session_mutex);

    std::cout << "[OTP] SUCCESS for user '" << pending.username
              << "' – session_id=" << session_id.substr(0, 16) << "...\n";

    // ── Grant authenticated session (dashboard) ──────────────────────────────
    std::string dashboard =
        "<html><head><title>Dashboard – RaceIoT Gateway</title></head><body>"
        "<h1>Login Successful</h1>"
        "<p>Welcome, <strong>" + pending.username + "</strong>! "
        "Identity verified by TOTP and recorded on the blockchain.</p>"
        "<p><small>Blockchain session ID: " + session_id.substr(0, 16) + "...</small></p>"
        "<hr/>"
        "<h2>IoT Gateway Dashboard</h2>"
        "<h3>Firmware Upload</h3>"
        "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">"
        "<input type=\"file\" name=\"file\"/>"
        "<input type=\"submit\" value=\"Upload\"/>"
        "</form>"
        "<h3>LED Control</h3>"
        "<p><a href=\"/startledblink?speed=5\">Blink 5s</a> | "
        "<a href=\"/startledblink?speed=1\">Blink 1s</a> | "
        "<a href=\"/stopledblink\">Stop LED</a></p>"
        "<hr/><p><a href=\"/login\">Log Out</a></p>"
        "</body></html>";

    // Clear the OTP session cookie
    struct MHD_Response* resp = MHD_create_response_from_buffer(
        dashboard.size(),
        const_cast<char*>(dashboard.c_str()),
        MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Set-Cookie",
        "iotgw_session=; HttpOnly; Secure; SameSite=Strict; Path=/otp; Max-Age=0");
    MHD_add_response_header(resp, "Content-Type", "text/html");
    MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

// Handle LED control request
MHD_Result HttpsServer::handleLedControl(struct MHD_Connection* connection, const char* url) {
    std::cout << "[LED Control] Request received: " << url << std::endl;
    
    // Parse speed parameter from URL: /startledblink?speed=X
    const char* speed_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "speed");
    
    std::string response_str;
    int status_code = MHD_HTTP_OK;
    
    if (speed_str != nullptr) {
        try {
            int speed = std::stoi(speed_str);
            
            // Validate speed (1-60 seconds)
            if (speed >= 1 && speed <= 60) {
                led_blink_speed.store(speed);
                
                response_str = "{\n";
                response_str += "  \"status\": \"success\",\n";
                response_str += "  \"message\": \"LED blink speed updated\",\n";
                response_str += "  \"speed\": " + std::to_string(speed) + ",\n";
                response_str += "  \"unit\": \"seconds\"\n";
                response_str += "}\n";
                
                std::cout << "[LED Control] Speed set to " << speed << " seconds" << std::endl;
            } else {
                response_str = "{\n";
                response_str += "  \"status\": \"error\",\n";
                response_str += "  \"message\": \"Speed must be between 1 and 60 seconds\"\n";
                response_str += "}\n";
                status_code = MHD_HTTP_BAD_REQUEST;
                
                std::cerr << "[LED Control] Invalid speed value: " << speed << std::endl;
            }
        } catch (const std::exception& e) {
            response_str = "{\n";
            response_str += "  \"status\": \"error\",\n";
            response_str += "  \"message\": \"Invalid speed parameter\"\n";
            response_str += "}\n";
            status_code = MHD_HTTP_BAD_REQUEST;
            
            std::cerr << "[LED Control] Exception: " << e.what() << std::endl;
        }
    } else {
        // No speed parameter, return current speed
        int current_speed = led_blink_speed.load();
        
        response_str = "{\n";
        response_str += "  \"status\": \"info\",\n";
        response_str += "  \"message\": \"Current LED blink speed\",\n";
        response_str += "  \"speed\": " + std::to_string(current_speed) + ",\n";
        response_str += "  \"unit\": \"seconds\",\n";
        response_str += "  \"usage\": \"Add ?speed=X parameter to change (1-60 seconds)\"\n";
        response_str += "}\n";
        
        std::cout << "[LED Control] Current speed query: " << current_speed << " seconds" << std::endl;
    }
    
    return sendResponse(connection, response_str, status_code);
}

// Send HTTP response
MHD_Result HttpsServer::sendResponse(struct MHD_Connection* connection, 
                                     const std::string& content, 
                                     int status_code) {
    struct MHD_Response* response = MHD_create_response_from_buffer(
        content.length(),
        const_cast<char*>(content.c_str()),
        MHD_RESPMEM_MUST_COPY
    );
    // print response creation
    std::cout << "Sending response with status code: " << status_code << std::endl;

    MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// Main request handler
MHD_Result HttpsServer::answerToConnection(void* cls, struct MHD_Connection* connection,
                                          const char* url, const char* method,
                                          const char* version, const char* upload_data,
                                          size_t* upload_data_size, void** con_cls) {
    // Initialize connection info on first call
    if (*con_cls == nullptr) {
        ConnectionInfo* con_info = new ConnectionInfo();
        
        if (std::strcmp(method, "POST") == 0) {
            // Mark as POST request
            std::cout << "Marking connection as POST request" << std::endl;
            con_info->setIsPost(true);
        }
        
        *con_cls = con_info;
        return MHD_YES;
    }
    
    ConnectionInfo* con_info = static_cast<ConnectionInfo*>(*con_cls);
    
    // Handle POST upload
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/upload") == 0) {
        std::cout << "Handling POST upload request..." << std::endl;
        return handlePostUpload(connection, con_info, upload_data, upload_data_size);
    }

    // Handle POST /register
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/register") == 0) {
        std::cout << "Handling POST register request..." << std::endl;
        return handleRegisterPost(connection, con_info, upload_data, upload_data_size);
    }

    // Handle POST /login
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/login") == 0) {
        std::cout << "Handling POST login request..." << std::endl;
        return handleLoginPost(connection, con_info, upload_data, upload_data_size);
    }

    // Handle POST /otp
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/otp") == 0) {
        std::cout << "Handling POST OTP request..." << std::endl;
        return handleOtpPost(connection, con_info, upload_data, upload_data_size);
    }

    // Handle GET or other methods
    if (std::strcmp(method, "GET") == 0) {
        std::cout << "Handling GET request for URL: " << url << std::endl;
        
        // LED control endpoint
        if (std::strcmp(url, "/startledblink") == 0 || 
            std::strncmp(url, "/startledblink?", 15) == 0) {
            return handleLedControl(connection, url);
        }
        
        // Default GET handler
        return handleGetRequest(connection, url);
    }
    
    // Method not allowed
    return sendResponse(connection, "Method not allowed", MHD_HTTP_METHOD_NOT_ALLOWED);
}
