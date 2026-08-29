#include "https_server.h"
#include "main.h"
#include "user_auth.h"
#include "otp_manager.h"
#include "blockchain_logger.h"
#include "firmwareupdate.h"

#include <iostream>
#include <fstream>
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
#include <sys/stat.h>
#include <openssl/evp.h>

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
// computeLocalFileHash  –  SHA-256 of a file; returns lowercase 64-char hex
// ---------------------------------------------------------------------------
static std::string computeLocalFileHash(const std::string& path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return "";
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) { EVP_MD_CTX_free(ctx); return ""; }
    char buf[65536];
    while (ifs.read(buf, sizeof(buf)) || ifs.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(ifs.gcount()));
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len); EVP_MD_CTX_free(ctx);
    std::ostringstream hex; hex << std::hex;
    for (unsigned int i = 0; i < len; ++i) { hex.width(2); hex.fill('0'); hex << static_cast<unsigned int>(digest[i]); }
    return hex.str();
}

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
            MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS,
            port,
            nullptr, nullptr,
            &HttpsServer::answerToConnection, this,
            MHD_OPTION_HTTPS_MEM_CERT,  cert_pem,
            MHD_OPTION_HTTPS_MEM_KEY,   key_pem,
            MHD_OPTION_HTTPS_MEM_TRUST, trust_pem,   // sets trust store; requests client cert
            MHD_OPTION_NOTIFY_COMPLETED, HttpsServer::requestCompleted, nullptr,
            MHD_OPTION_END
        );
        // Store flag so answerToConnection can enforce client cert at app layer.
        // GnuTLS with MHD_OPTION_HTTPS_MEM_TRUST requests a client cert but does
        // not reject the connection when none is provided (GNUTLS_CERT_REQUIRE is
        // not set by libmicrohttpd). We therefore check gnutls_certificate_get_peers()
        // inside the HTTP handler and return 403 for any request that arrives
        // without a certificate signed by the trusted Root CA.
        this->mtls_enabled = true;
    } else {
        // mTLS not available — start without client-cert requirement.
        // Suitable for local development; NOT recommended for production.
        std::cerr << "[mTLS] WARNING: Starting without client-cert enforcement."
                     " Direct port-8443 access is not blocked." << std::endl;
        daemon = MHD_start_daemon(
            MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS,
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
        std::cerr << "\n[HTTPS ERROR] Failed to start HTTPS server on port " << port << std::endl;
        std::cerr << "  Binding address: " << bind_address << std::endl;
        std::cerr << "  mTLS enforcement: " << (mtls_enabled ? "ENABLED" : "DISABLED") << std::endl;
        std::cerr << "  Certificate loaded: " << (cert_pem ? "YES" : "NO") << std::endl;
        std::cerr << "  Key loaded: " << (key_pem ? "YES" : "NO") << std::endl;
        std::cerr << "  CA loaded: " << (trust_pem ? "YES" : "NO") << std::endl;
        std::cerr << "\n[DEBUG] Possible causes:" << std::endl;
        std::cerr << "  1. Port " << port << " already in use (check: lsof -i :" << port << ")" << std::endl;
        std::cerr << "  2. Certificate/key format invalid (verify with: openssl x509 -in /path/to/cert.crt -text)" << std::endl;
        std::cerr << "  3. GnuTLS/libmicrohttpd incompatibility (check library versions)" << std::endl;
        std::cerr << "  4. Insufficient permissions to bind to port " << port << std::endl;
        std::cerr << "  5. libmicrohttpd not built with TLS support" << std::endl;
        std::cerr << "  System errno: " << strerror(errno) << "\n" << std::endl;
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

    // --- Config upload page ---
    if (std::strcmp(url, "/config-upload") == 0)
        return handleConfigUploadGet(connection);

    // --- Landing page (default) ---
    std::string page =
        "<html><body>"
        "<h1>RaceIoT Device</h1>"
        "<p>Welcome! Please register or log in to continue.</p>"
        "<a href=\"/register\"><button>Register</button></a>&nbsp;&nbsp;"
        "<a href=\"/login\"><button>Login</button></a>"
        "<hr/>"
        "<h2>&#9881; First-Time Setup</h2>"
        "<p>Upload device configuration files (firmware.conf, blockchain.conf, keys, RAUC certs).</p>"
        "<a href=\"/config-upload\"><button style='background:#e67e22;color:#fff;padding:8px 18px;"
        "border:none;border-radius:5px;font-size:1em;cursor:pointer;'>&#128196; Upload Config Files</button></a>"
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

    // Blockchain is used for audit logging only — its availability does NOT
    // gate authentication. Login proceeds whether or not the chain is reachable.
    // logEvent() calls below are fire-and-forget; if the chain is unreachable
    // they are queued locally and replayed automatically when it returns.
    std::string bc_status_msg;
    if (s_blockchain) {
        std::string bc_err;
        bool bc_ok = s_blockchain->checkConnectivity(bc_err);
        if (!bc_ok) {
            bc_status_msg = "[Login] Blockchain unreachable (" + bc_err +
                            ") — event queued, auth continues normally.\n";
            std::cerr << bc_status_msg;
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
            time_t elapsed = std::time(nullptr) - pf->second.lock_time;
            if (elapsed >= LOCKOUT_DURATION_SECS) {
                // Cooldown expired — auto-unlock
                s_pass_fails.erase(pf);
                pthread_mutex_unlock(&s_session_mutex);
                addActivityLog("[LOGIN] Lockout expired for '" + username + "' — auto-unlocked");
            } else {
                long mins_remaining = (LOCKOUT_DURATION_SECS - elapsed + 59) / 60;
                long secs_remaining = LOCKOUT_DURATION_SECS - static_cast<long>(elapsed);
                pthread_mutex_unlock(&s_session_mutex);
                addActivityLog("[LOGIN] Account locked (password) for '" + username + "'");
                return sendResponse(connection,
                    "<!DOCTYPE html><html lang=\"en\">"
                    "<head><meta charset=\"UTF-8\"><title>Account Locked</title>"
                    "<style>"
                    "body{margin:0;font-family:Arial,sans-serif;background:#f0f2f5;"
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;}"
                    ".overlay{position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;"
                    "justify-content:center;align-items:center;z-index:999;}"
                    ".modal{background:#fff;border-radius:12px;padding:40px 36px;max-width:420px;"
                    "width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.25);text-align:center;}"
                    ".icon{font-size:3.5em;margin-bottom:12px;}"
                    "h2{margin:0 0 10px;color:#c0392b;font-size:1.4em;}"
                    "p{color:#555;line-height:1.6;margin:8px 0;}"
                    ".countdown{font-size:2em;font-weight:bold;color:#c0392b;"
                    "margin:18px 0;letter-spacing:2px;}"
                    ".label{font-size:0.85em;color:#888;margin-bottom:20px;}"
                    ".btn{display:inline-block;margin-top:10px;padding:10px 28px;"
                    "background:#3498db;color:#fff;text-decoration:none;"
                    "border-radius:6px;font-size:1em;border:none;cursor:pointer;}"
                    ".btn:hover{background:#2980b9;}"
                    ".progress-bar{width:100%;background:#f0f0f0;border-radius:999px;"
                    "height:8px;margin:16px 0;overflow:hidden;}"
                    ".progress-fill{height:100%;background:#c0392b;border-radius:999px;"
                    "transition:width 1s linear;}"
                    "</style></head>"
                    "<body>"
                    "<div class=\"overlay\">"
                    "<div class=\"modal\">"
                    "<div class=\"icon\">&#128274;</div>"
                    "<h2>Account Temporarily Locked</h2>"
                    "<p>Too many failed password attempts.<br/>Your account is locked for <strong>30 minutes</strong>.</p>"
                    "<div class=\"countdown\" id=\"timer\">--:--</div>"
                    "<div class=\"label\">remaining before you can try again</div>"
                    "<div class=\"progress-bar\"><div class=\"progress-fill\" id=\"bar\"></div></div>"
                    "<p style=\"font-size:0.82em;color:#aaa;\">This page will automatically redirect when the lockout expires.</p>"
                    "<a href=\"/login\" class=\"btn\">&#8592; Back to Login</a>"
                    "</div></div>"
                    "<script>"
                    "var total=" + std::to_string(secs_remaining) + ";"
                    "var maxSecs=" + std::to_string(LOCKOUT_DURATION_SECS) + ";"
                    "function fmt(s){"
                    "  var m=Math.floor(s/60),sec=s%60;"
                    "  return (m<10?'0':'')+m+':'+(sec<10?'0':'')+sec;"
                    "}"
                    "function tick(){"
                    "  if(total<=0){window.location.href='/login';return;}"
                    "  document.getElementById('timer').textContent=fmt(total);"
                    "  var pct=Math.round((total/maxSecs)*100);"
                    "  document.getElementById('bar').style.width=pct+'%';"
                    "  total--;setTimeout(tick,1000);"
                    "}"
                    "tick();"
                    "</script>"
                    "</body></html>",
                    MHD_HTTP_FORBIDDEN);
            }
        } else {
            pthread_mutex_unlock(&s_session_mutex);
        }
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
        if (rec.count >= MAX_PASSWORD_FAILS) {
            rec.locked    = true;
            rec.lock_time = std::time(nullptr);
        }
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

    // Blockchain is used for audit logging only — its availability does NOT
    // gate OTP verification. TOTP is validated locally regardless of chain state.
    // Events are queued and replayed automatically when the chain returns.
    if (s_blockchain) {
        std::string bc_err;
        bool bc_ok = s_blockchain->checkConnectivity(bc_err);
        if (!bc_ok) {
            std::cerr << "[OTP] Blockchain unreachable (" << bc_err
                      << ") — event queued, OTP verification continues normally.\n";
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

    // ── Check OTP account lockout (persistent 30-min cooldown, same as password) ──
    // When OTP fails 3x, account is locked for 30 minutes, not just the session.
    // This mirrors password failure behavior for symmetrical security.
    {
        pthread_mutex_lock(&s_session_mutex);
        auto pf = s_pass_fails.find(pending.username);
        if (pf != s_pass_fails.end() && pf->second.locked) {
            time_t elapsed = std::time(nullptr) - pf->second.lock_time;
            if (elapsed >= LOCKOUT_DURATION_SECS) {
                // Cooldown expired — auto-unlock
                s_pass_fails.erase(pf);
                pthread_mutex_unlock(&s_session_mutex);
                addActivityLog("[OTP] Lockout expired for '" + pending.username + "' — auto-unlocked");
            } else {
                long secs_remaining = LOCKOUT_DURATION_SECS - static_cast<long>(elapsed);
                pthread_mutex_unlock(&s_session_mutex);
                addActivityLog("[OTP] Account locked (from OTP failures) for '" + pending.username + "'");
                // Return 403 with countdown modal (same as password lockout)
                return sendResponse(connection,
                    "<!DOCTYPE html><html lang=\"en\">"
                    "<head><meta charset=\"UTF-8\"><title>Account Locked</title>"
                    "<style>"
                    "body{margin:0;font-family:Arial,sans-serif;background:#f0f2f5;"
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;}"
                    ".overlay{position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;"
                    "justify-content:center;align-items:center;z-index:999;}"
                    ".modal{background:#fff;border-radius:12px;padding:40px 36px;max-width:420px;"
                    "width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.25);text-align:center;}"
                    ".icon{font-size:3.5em;margin-bottom:12px;}"
                    "h2{margin:0 0 10px;color:#c0392b;font-size:1.4em;}"
                    "p{color:#555;line-height:1.6;margin:8px 0;}"
                    ".countdown{font-size:2em;font-weight:bold;color:#c0392b;"
                    "margin:18px 0;letter-spacing:2px;}"
                    ".label{font-size:0.85em;color:#888;margin-bottom:20px;}"
                    ".btn{display:inline-block;margin-top:10px;padding:10px 28px;"
                    "background:#3498db;color:#fff;text-decoration:none;"
                    "border-radius:6px;font-size:1em;border:none;cursor:pointer;}"
                    ".btn:hover{background:#2980b9;}"
                    ".progress-bar{width:100%;background:#f0f0f0;border-radius:999px;"
                    "height:8px;margin:16px 0;overflow:hidden;}"
                    ".progress-fill{height:100%;background:#c0392b;border-radius:999px;"
                    "transition:width 1s linear;}"
                    "</style></head>"
                    "<body>"
                    "<div class=\"overlay\">"
                    "<div class=\"modal\">"
                    "<div class=\"icon\">&#128274;</div>"
                    "<h2>Account Temporarily Locked</h2>"
                    "<p>Too many failed OTP attempts.<br/>Your account is locked for <strong>30 minutes</strong>.</p>"
                    "<div class=\"countdown\" id=\"timer\">--:--</div>"
                    "<div class=\"label\">remaining before you can try again</div>"
                    "<div class=\"progress-bar\"><div class=\"progress-fill\" id=\"bar\"></div></div>"
                    "<p style=\"font-size:0.82em;color:#aaa;\">This page will automatically redirect when the lockout expires.</p>"
                    "<a href=\"/login\" class=\"btn\">&#8592; Back to Login</a>"
                    "</div></div>"
                    "<script>"
                    "var total=" + std::to_string(secs_remaining) + ";"
                    "var maxSecs=" + std::to_string(LOCKOUT_DURATION_SECS) + ";"
                    "function fmt(s){"
                    "  var m=Math.floor(s/60),sec=s%60;"
                    "  return (m<10?'0':'')+m+':'+(sec<10?'0':'')+sec;"
                    "}"
                    "function tick(){"
                    "  if(total<=0){window.location.href='/login';return;}"
                    "  document.getElementById('timer').textContent=fmt(total);"
                    "  var pct=Math.round((total/maxSecs)*100);"
                    "  document.getElementById('bar').style.width=pct+'%';"
                    "  total--;setTimeout(tick,1000);"
                    "}"
                    "tick();"
                    "</script>"
                    "</body></html>",
                    MHD_HTTP_FORBIDDEN);
            }
        } else {
            pthread_mutex_unlock(&s_session_mutex);
        }
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

        // Log OTP_FAIL to blockchain (fire-and-forget, queues if offline)
        if (s_blockchain) {
            s_blockchain->logEvent(pending.username, BlockchainLogger::OTP_FAIL, session_id);
            addActivityLog("[BLOCKCHAIN] OTP_FAIL logged for '" + pending.username + "' (queued if offline)");
        }
        addActivityLog("[OTP] Wrong code for '" + pending.username + "' ("
            + std::to_string(pending.local_fails) + "/" + std::to_string(MAX_LOCAL_OTP_FAILS) + " fails)");

        std::cerr << "[OTP] Wrong OTP for '" << pending.username
                  << "' (local fail " << pending.local_fails << "/" << MAX_LOCAL_OTP_FAILS << ")\n";

        // If 3 OTP failures reached, lock the entire account (30-min cooldown)
        // This mirrors password failure behavior for symmetrical security
        if (pending.local_fails >= MAX_LOCAL_OTP_FAILS) {
            // Activate buzzer on GPIO 18 (BCM) via Linux sysfs.
            // Runs in a detached background thread so the HTTP response
            // is not blocked during the 5-second buzzer sequence.
            {
                // Play lockout alert audio via mpg123 (detached, non-blocking)
                pthread_t audio_thread;
                pthread_attr_t audio_attr;
                pthread_attr_init(&audio_attr);
                pthread_attr_setdetachstate(&audio_attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&audio_thread, &audio_attr, [](void*) -> void* {
                    system("mpg123 -o alsa -q /usr/share/iot-gateway/lockout.mp3");
                    return nullptr;
                }, nullptr);
                pthread_attr_destroy(&audio_attr);

                // Activate buzzer on GPIO 18 (BCM) via Linux sysfs (detached, non-blocking)
                pthread_t buzz_thread;
                pthread_attr_t buzz_attr;
                pthread_attr_init(&buzz_attr);
                pthread_attr_setdetachstate(&buzz_attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&buzz_thread, &buzz_attr, [](void*) -> void* {
                    // Export GPIO 18
                    if (FILE* fp = fopen("/sys/class/gpio/export", "w")) {
                        fputs("18", fp);
                        fclose(fp);
                    }
                    // Allow the kernel time to create the gpio18 sysfs entry
                    usleep(100000);
                    // Set pin direction to output
                    if (FILE* fp = fopen("/sys/class/gpio/gpio18/direction", "w")) {
                        fputs("out", fp);
                        fclose(fp);
                    }
                    // Sound buzzer: 5 pulses × (0.5 s HIGH + 0.5 s LOW)
                    for (int i = 0; i < 5; ++i) {
                        if (FILE* fp = fopen("/sys/class/gpio/gpio18/value", "w")) {
                            fputs("1", fp);
                            fclose(fp);
                        }
                        usleep(500000);
                        if (FILE* fp = fopen("/sys/class/gpio/gpio18/value", "w")) {
                            fputs("0", fp);
                            fclose(fp);
                        }
                        usleep(500000);
                    }
                    // Unexport GPIO 18 to release the pin
                    if (FILE* fp = fopen("/sys/class/gpio/unexport", "w")) {
                        fputs("18", fp);
                        fclose(fp);
                    }
                    return nullptr;
                }, nullptr);
                pthread_attr_destroy(&buzz_attr);
            }

            pthread_mutex_lock(&s_session_mutex);
            PasswordFailRecord& account_lock = s_pass_fails[pending.username];
            account_lock.count    = MAX_PASSWORD_FAILS;  // Set to max to trigger lock
            account_lock.locked   = true;
            account_lock.lock_time = std::time(nullptr); // Set lock timestamp
            pthread_mutex_unlock(&s_session_mutex);

            // Log LOCKOUT event to blockchain (fire-and-forget, queues if offline)
            if (s_blockchain) {
                s_blockchain->logEvent(pending.username, BlockchainLogger::LOCKOUT, session_id);
                addActivityLog("[BLOCKCHAIN] LOCKOUT event logged (OTP threshold) — queued if offline");
            }
            addActivityLog("[OTP] Account now locked for 30 min (3 OTP failures for '" + pending.username + "')");
            std::cerr << "[OTP] Account LOCKED (OTP failures) for user: " << pending.username << "\n";
        }

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
        "<h3>Firmware Update</h3>"
        "<a href='/fw-check'>"
        "<button style='padding:10px 20px;background:#27ae60;color:#fff;border:none;"
        "border-radius:6px;font-size:1em;cursor:pointer;'>"
        "&#128190; Check Blockchain for Latest Firmware</button></a>"
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

// ---------------------------------------------------------------------------
// handleFirmwareProgress  –  GET /fw-progress
//   Returns a JSON object with the current firmware update status and download
//   progress percentage so the browser's progress bar can poll it.
// ---------------------------------------------------------------------------
MHD_Result HttpsServer::handleFirmwareProgress(struct MHD_Connection* connection)
{
    FirmwareUpdateManager* fw = fw_manager;  // global set by firmwareUpdateThread
    std::string status_str = "IDLE";
    int  progress = 0;
    bool done     = false;

    if (fw) {
        FirmwareUpdateStatus st = fw->getStatus();
        status_str = firmwareStatusLabel(st);
        switch (st) {
            case FirmwareUpdateStatus::DOWNLOADING:
                progress = fw->getDownloadProgress();
                if (progress < 0) progress = 0;
                break;
            case FirmwareUpdateStatus::VERIFYING:  progress = 100; break;
            case FirmwareUpdateStatus::APPLYING:   progress = 100; break;
            case FirmwareUpdateStatus::SUCCESS:    progress = 100; done = true; break;
            case FirmwareUpdateStatus::FAILED:     progress = 0;   done = true; break;
            default: progress = 0; break;
        }
    }

    std::string json = "{\"status\":\"" + status_str + "\","
                       "\"progress\":" + std::to_string(progress) + ","
                       "\"done\":"     + (done ? "true" : "false") + ","
                       "\"error\":\""  + (fw ? fw->getLastError() : "") + "\"}";

    struct MHD_Response* resp = MHD_create_response_from_buffer(
        json.size(), const_cast<char*>(json.c_str()), MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Cache-Control", "no-store");
    MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

// ---------------------------------------------------------------------------
// handleFirmwareCheck  –  GET /fw-check
//   Displays the full blockchain access report: node connectivity, OEM/fleet
//   approval chain, hash/version comparison, and install permission decision.
// ---------------------------------------------------------------------------
MHD_Result HttpsServer::handleFirmwareCheck(struct MHD_Connection* connection)
{
    // ── Read firmware.conf ────────────────────────────────────────────────
    std::string fw_contract_addr;
    std::string fw_hsm_pubkey = "/etc/googlehsmkey/hsm-pubkey.pem";
    std::string ca_cert       = "/etc/ssl/certs/ca-certificates.crt";

    std::ifstream conf("/etc/iot-gateway/firmware.conf");
    if (conf.is_open()) {
        std::string ln;
        while (std::getline(conf, ln)) {
            if (ln.empty() || ln[0] == '#') continue;
            auto eq = ln.find('=');
            if (eq == std::string::npos) continue;
            std::string k = ln.substr(0, eq), v = ln.substr(eq + 1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\t')) v.pop_back();
            if      (k == "FIRMWARE_CONTRACT")   fw_contract_addr = v;
            else if (k == "FIRMWARE_HSM_PUBKEY") fw_hsm_pubkey    = v;
            else if (k == "FIRMWARE_CA_CERT")    ca_cert          = v;
        }
    }

    // ── Step 1: Blockchain connectivity check ─────────────────────────────
    bool bc_reachable = false;
    std::string bc_detail;
    if (s_blockchain) {
        bc_reachable = s_blockchain->checkConnectivity(bc_detail);
        if (bc_reachable) bc_detail = s_blockchain->getStatusString();
    } else {
        bc_detail = "Blockchain logger not initialised — check blockchain.conf";
    }

    const std::string CSS =
        "body{font-family:Arial,sans-serif;padding:24px;max-width:900px;margin:auto;background:#f8f9fa;}"
        "h1{color:#2c3e50;margin-bottom:4px;}h2{color:#34495e;margin-top:28px;margin-bottom:10px;}"
        ".card{background:#fff;border-radius:8px;box-shadow:0 1px 6px rgba(0,0,0,0.10);padding:18px 22px;margin:14px 0;}"
        "table{width:100%;border-collapse:collapse;font-size:0.9em;}"
        "th{background:#f0f4f8;text-align:left;padding:8px 12px;color:#555;}"
        "td{padding:8px 12px;border-bottom:1px solid #f0f0f0;word-break:break-all;}"
        ".tag{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.82em;font-weight:bold;}"
        ".tag-ok{background:#d4edda;color:#155724;}"
        ".tag-warn{background:#fff3cd;color:#856404;}"
        ".tag-block{background:#f8d7da;color:#721c24;}"
        ".tag-info{background:#cce5ff;color:#004085;}"
        ".verdict{border-radius:8px;padding:18px 22px;margin:20px 0;font-size:1.08em;}"
        ".verdict-ok{background:#d4edda;color:#155724;border-left:5px solid #28a745;}"
        ".verdict-block{background:#f8d7da;color:#721c24;border-left:5px solid #dc3545;}"
        ".verdict-warn{background:#fff3cd;color:#856404;border-left:5px solid #ffc107;}"
        ".btn{display:inline-block;padding:11px 26px;border-radius:6px;border:none;cursor:pointer;font-size:1em;text-decoration:none;margin:6px 4px;}"
        ".btn-go{background:#27ae60;color:#fff;}"
        ".btn-back{background:#3498db;color:#fff;}"
        ".blocked-notice{background:#f8d7da;border:2px solid #dc3545;border-radius:8px;"
        "padding:18px 22px;margin:20px 0;color:#721c24;}";

    // ── Section 1: Blockchain access report ───────────────────────────────
    std::string bc_tag   = bc_reachable
        ? "<span class='tag tag-ok'>&#9989; CONNECTED</span>"
        : "<span class='tag tag-block'>&#10060; UNREACHABLE</span>";
    std::string conf_tag = fw_contract_addr.empty()
        ? "<span class='tag tag-block'>&#10060; NOT CONFIGURED</span>"
        : "<span class='tag tag-ok'>&#9989; " + fw_contract_addr.substr(0, 10) + "...</span>";

    std::string page =
        "<!DOCTYPE html><html lang='en'>"
        "<head><meta charset='UTF-8'><title>Firmware Update Report</title>"
        "<style>" + CSS + "</style></head><body>"
        "<h1>&#128202; Firmware Update Report</h1>"
        "<p style='color:#666;font-size:0.9em;'>Live check against Ethereum blockchain ledger</p>"

        "<div class='card'>"
        "<h2>&#128279; Blockchain Access</h2>"
        "<table><tr><th>Parameter</th><th>Status</th></tr>"
        "<tr><td>Ethereum Node</td><td>" + bc_tag + "<br/>"
            "<small style='color:#888;'>" + bc_detail + "</small></td></tr>"
        "<tr><td>FirmwareMetadataStore Contract</td><td>" + conf_tag + "</td></tr>"
        "</table></div>";

    // If blockchain is unreachable or contract not configured, stop here
    if (!bc_reachable || fw_contract_addr.empty()) {
        page +=
            "<div class='blocked-notice'>"
            "<strong style='font-size:1.1em;'>&#128683; Download &amp; Install: NOT ALLOWED</strong><br/><br/>"
            + std::string(!bc_reachable
                ? "The Ethereum blockchain node is unreachable. The OEM approval status cannot be "
                  "verified. Firmware download and installation are <strong>blocked</strong> until "
                  "the blockchain is accessible."
                : "No <code>FIRMWARE_CONTRACT</code> address is configured in "
                  "<code>/etc/iot-gateway/firmware.conf</code>. The firmware metadata ledger "
                  "cannot be queried.")
            + "</div>"
            "<a href='/fw-check' class='btn btn-back'>&#8635; Retry</a>&nbsp;"
            "<a href='/status'  class='btn btn-back'>&#8592; System Status</a>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_SERVICE_UNAVAILABLE);
    }

    // ── Step 2: Read latest metadata from blockchain ledger ───────────────
    FirmwareInfo info = s_blockchain->readLatestFirmwareMetadata(fw_contract_addr);
    if (!info.error.empty()) {
        page +=
            "<div class='blocked-notice'>"
            "<strong style='font-size:1.1em;'>&#128683; Download &amp; Install: NOT ALLOWED</strong><br/><br/>"
            "Blockchain query failed: " + info.error +
            " <strong>Deploy the FirmwareMetadataStore contract on the connected RPC chain and register at least one firmware release before OTA can proceed.</strong>"
            "</div>"
            "<a href='/fw-check' class='btn btn-back'>&#8635; Retry</a>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_SERVICE_UNAVAILABLE);
    }

    // ── Step 3: OEM / Fleet approval report ───────────────────────────────
    bool oem_approved   = (info.approval_stage >= ApprovalStage::OEM_APPROVED);
    bool fleet_released = (info.approval_stage >= ApprovalStage::FLEET_RELEASED);

    std::string stage_tag;
    if (fleet_released)
        stage_tag = "<span class='tag tag-ok'>&#9989; FLEET_RELEASED</span>";
    else if (oem_approved)
        stage_tag = "<span class='tag tag-info'>&#128203; OEM_APPROVED</span>";
    else
        stage_tag = "<span class='tag tag-block'>&#128683; SUPPLIER_REGISTERED (pending)</span>";

    std::string oem_row =
        oem_approved
        ? "<span class='tag tag-ok'>&#9989; APPROVED</span>"
          " &nbsp;<small>" + info.approved_by_oem + " &bull; " + info.oem_approved_at + "</small>"
        : "<span class='tag tag-block'>&#10060; NOT YET APPROVED</span>"
          " &nbsp;<small style='color:#888;'>OEM has not reviewed this firmware</small>";

    std::string fleet_row =
        fleet_released
        ? "<span class='tag tag-ok'>&#9989; RELEASED</span>"
          " &nbsp;<small>" + info.approved_by_fleet + " &bull; " + info.fleet_approved_at + "</small>"
        : (oem_approved
            ? "<span class='tag tag-warn'>&#9203; PENDING</span>"
              " &nbsp;<small style='color:#888;'>Awaiting fleet operator release</small>"
            : "<span class='tag tag-block'>&#10060; BLOCKED</span>"
              " &nbsp;<small style='color:#888;'>OEM must approve first</small>");

    page +=
        "<div class='card'>"
        "<h2>&#9989; OEM &amp; Fleet Approval Chain</h2>"
        "<table><tr><th>Stage</th><th>Result</th></tr>"
        "<tr><td>Overall Approval Stage</td><td>" + stage_tag + "</td></tr>"
        "<tr><td>1. OEM Approval</td><td>" + oem_row + "</td></tr>"
        "<tr><td>2. Fleet Operator Release</td><td>" + fleet_row + "</td></tr>"
        "<tr><td>Firmware Version</td><td><strong>" + info.firmware_version + "</strong></td></tr>"
        "<tr><td>Signed By</td><td>" + info.signer_identity + "</td></tr>"
        "<tr><td>Registered At</td><td>" + info.timestamp + "</td></tr>"
        "</table></div>";

    // ── Step 4: Hash / version comparison ────────────────────────────────
    std::string current_hash    = computeLocalFileHash("/usr/bin/iot-gateway");
    std::string current_version = fw_manager ? fw_manager->getCurrentVersion() : "0.0.0";
    std::string bc_hash_hex     = info.firmware_hash;
    if (bc_hash_hex.size() > 7 && bc_hash_hex.substr(0, 7) == "sha256:")
        bc_hash_hex = bc_hash_hex.substr(7);

    bool hash_differs  = current_hash.empty() || (current_hash != bc_hash_hex);
    bool version_newer = (FirmwareUpdateManager::compareSemver(info.firmware_version, current_version) > 0);

    page +=
        "<div class='card'>"
        "<h2>&#128190; Firmware Comparison</h2>"
        "<table><tr><th>Field</th><th>Blockchain (latest)</th><th>Running on device</th></tr>"
        "<tr><td>Version</td>"
        "<td><strong>" + info.firmware_version + "</strong>"
            + (version_newer ? " <span class='tag tag-ok'>newer</span>"
                             : " <span class='tag tag-warn'>not newer</span>") + "</td>"
        "<td>" + current_version + "</td></tr>"
        "<tr><td>SHA-256</td>"
        "<td style='font-family:monospace;font-size:0.78em;'>" + (bc_hash_hex.size() > 16 ? bc_hash_hex.substr(0,16)+"..." : bc_hash_hex) + "</td>"
        "<td style='font-family:monospace;font-size:0.78em;'>"
            + (current_hash.empty() ? "<i style='color:red;'>error</i>" : current_hash.substr(0,16)+"...") + "</td></tr>"
        "<tr><td>Hash match?</td>"
        "<td colspan='2'>" + (hash_differs
            ? "<span class='tag tag-ok'>&#9989; Different — update available</span>"
            : "<span class='tag tag-info'>&#9989; Identical — already up to date</span>") + "</td></tr>"
        "<tr><td>Download URL</td><td colspan='2' style='font-size:0.85em;'>" + info.download_url + "</td></tr>"
        "</table></div>";

    // ── Step 5: Install permission decision ───────────────────────────────
    bool eligible = hash_differs && version_newer && oem_approved;

    if (eligible) {
        page +=
            "<div class='verdict verdict-ok'>"
            "<strong style='font-size:1.15em;'>&#9989; Download &amp; Install: ALLOWED</strong><br/>"
            "All conditions satisfied: firmware is newer, hash differs, and OEM has approved.<br/>"
            "<small>Install sequence: HTTPS download &rarr; Google HSM signature verify "
            "&rarr; LDR header validate &rarr; SHA-256 check &rarr; atomic install</small>"
            "</div>"
            "<form action='/fw-update-trigger' method='post'>"
            "<button type='submit' class='btn btn-go'>&#128197; Install Firmware "
            + info.firmware_version + "</button></form>";
    } else {
        // Build specific reason
        std::string reason;
        if (!oem_approved)
            reason = "OEM has <strong>not approved</strong> this firmware. "
                     "The approval stage is <em>" + std::string(approvalStageLabel(info.approval_stage)) +
                     "</em>. An OEM administrator must call <code>approveByOem()</code> on the "
                     "FirmwareMetadataStore contract before this firmware can be downloaded or installed.";
        else if (!version_newer)
            reason = "The blockchain firmware version <strong>" + info.firmware_version +
                     "</strong> is not newer than the currently running version <strong>" +
                     current_version + "</strong>. No update is needed.";
        else
            reason = "The running firmware hash already matches the blockchain record. The device is up to date.";

        page +=
            "<div class='blocked-notice'>"
            "<strong style='font-size:1.15em;'>&#128683; Download &amp; Install: NOT ALLOWED</strong><br/><br/>"
            + reason +
            "</div>";
    }

    page += "<br/><a href='/fw-check' class='btn btn-back'>&#8635; Refresh</a>&nbsp;"
            "<a href='/status' class='btn btn-back'>&#8592; System Status</a>"
            "</body></html>";

    addActivityLog("[FIRMWARE] Web report: " + info.firmware_version +
                   " stage=" + approvalStageLabel(info.approval_stage) +
                   " eligible=" + (eligible ? "YES" : "NO"));
    return sendResponse(connection, page, MHD_HTTP_OK);
}

// ---------------------------------------------------------------------------
// handleFirmwareTrigger  –  POST /fw-update-trigger
//   Re-validates eligibility then calls fw_manager->startUpdate().
// ---------------------------------------------------------------------------
MHD_Result HttpsServer::handleFirmwareTrigger(struct MHD_Connection* connection,
                                               ConnectionInfo* con_info,
                                               const char* upload_data,
                                               size_t* upload_data_size)
{
    if (*upload_data_size > 0) { *upload_data_size = 0; return MHD_YES; }

    if (!s_blockchain || !fw_manager) {
        return sendResponse(connection,
            "<html><body><h1>Error</h1><p>Blockchain or firmware manager not available.</p>"
            "<p><a href='/fw-check'>Back</a></p></body></html>",
            MHD_HTTP_SERVICE_UNAVAILABLE);
    }

    std::string fw_contract_addr, fw_hsm_pubkey = "/etc/googlehsmkey/hsm-pubkey.pem";
    std::string ca_cert = "/etc/ssl/certs/ca-certificates.crt";
    std::string staging = "/tmp/iot-gateway.staging", target = "/usr/bin/iot-gateway";
    std::string backup  = "/usr/bin/iot-gateway.bak";

    std::ifstream conf("/etc/iot-gateway/firmware.conf");
    if (conf.is_open()) {
        std::string ln;
        while (std::getline(conf, ln)) {
            if (ln.empty() || ln[0] == '#') continue;
            auto eq = ln.find('=');
            if (eq == std::string::npos) continue;
            std::string k = ln.substr(0, eq), v = ln.substr(eq + 1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\t')) v.pop_back();
            if      (k == "FIRMWARE_CONTRACT")   fw_contract_addr = v;
            else if (k == "FIRMWARE_HSM_PUBKEY") fw_hsm_pubkey    = v;
            else if (k == "FIRMWARE_CA_CERT")    ca_cert          = v;
            else if (k == "FIRMWARE_STAGING")    staging          = v;
            else if (k == "FIRMWARE_TARGET")     target           = v;
            else if (k == "FIRMWARE_BACKUP")     backup           = v;
        }
    }

    if (fw_contract_addr.empty()) {
        return sendResponse(connection,
            "<html><body><h1>Error</h1><p>FIRMWARE_CONTRACT not configured.</p>"
            "<p><a href='/fw-check'>Back</a></p></body></html>",
            MHD_HTTP_BAD_REQUEST);
    }

    // Re-query blockchain to prevent stale data from the GET check page
    FirmwareInfo info = s_blockchain->readLatestFirmwareMetadata(fw_contract_addr);
    if (!info.error.empty()) {
        return sendResponse(connection,
            "<html><body><h1>Error</h1><p>Blockchain query failed: " + info.error + "</p>"
            "<p><a href='/fw-check'>Back</a></p></body></html>",
            MHD_HTTP_SERVICE_UNAVAILABLE);
    }

    if (info.approval_stage < ApprovalStage::OEM_APPROVED) {
        return sendResponse(connection,
            "<html><body><h1>Blocked</h1><p>Firmware not approved by OEM. Stage: "
            + std::string(approvalStageLabel(info.approval_stage)) + "</p>"
            "<p><a href='/fw-check'>Back</a></p></body></html>",
            MHD_HTTP_FORBIDDEN);
    }

    std::string bc_hash_hex = info.firmware_hash;
    if (bc_hash_hex.size() > 7 && bc_hash_hex.substr(0, 7) == "sha256:")
        bc_hash_hex = bc_hash_hex.substr(7);

    FirmwareUpdateConfig cfg;
    cfg.url             = info.download_url;
    cfg.version         = info.firmware_version;
    cfg.expected_sha256 = bc_hash_hex;
    cfg.ca_cert_path    = ca_cert;
    cfg.staging_path    = staging;
    cfg.target_path     = target;
    cfg.backup_path     = backup;
    cfg.hsm_pubkey_path = fw_hsm_pubkey;
    cfg.hsm_sig_url     = info.download_url + ".sig";
    cfg.bc_ldr_size_bytes     = info.final_image_size_bytes;  // full .ldr from blockchain
    cfg.bc_payload_size_bytes = info.image_size_bytes;        // payload (.raucb) from blockchain

    bool started = fw_manager->startUpdate(cfg);
    if (!started) {
        return sendResponse(connection,
            "<html><body><h1>Update Not Started</h1>"
            "<p>" + fw_manager->getLastError() + "</p>"
            "<p><a href='/fw-check'>Back</a></p></body></html>",
            MHD_HTTP_CONFLICT);
    }

    addActivityLog("[FIRMWARE] OTA triggered via dashboard → " + info.firmware_version +
                   " approval=" + approvalStageLabel(info.approval_stage));
    return sendResponse(connection,
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<title>Firmware Update</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;padding:24px;max-width:640px;margin:0 auto;}"
        ".bar-wrap{background:#e0e0e0;border-radius:8px;height:28px;overflow:hidden;margin:16px 0;}"
        ".bar{height:100%;background:linear-gradient(90deg,#1976d2,#42a5f5);width:0%;transition:width 0.4s;border-radius:8px;}"
        ".status{font-size:1.1em;margin:8px 0;} .pct{font-weight:bold;}"
        ".done-ok{color:#2e7d32;font-size:1.2em;font-weight:bold;}"
        ".done-err{color:#c62828;font-size:1.2em;font-weight:bold;}"
        ".btn{display:inline-block;padding:8px 18px;background:#1976d2;color:#fff;border-radius:6px;"
        "     text-decoration:none;margin-top:16px;}"
        "</style></head><body>"
        "<h1>&#128197; Firmware Update in Progress</h1>"
        "<p>Installing <strong>" + info.firmware_version + "</strong></p>"
        "<p class='status'>Status: <span id='st'>Downloading...</span></p>"
        "<div class='bar-wrap'><div class='bar' id='bar'></div></div>"
        "<p><span class='pct' id='pct'>0%</span> &mdash; "
        "<small>download &rarr; HSM verify &rarr; SHA-256 &rarr; RAUC install</small></p>"
        "<div id='msg'></div>"
        "<script>"
        "var tid=setInterval(function(){"
        "  fetch('/fw-progress').then(function(r){return r.json();}).then(function(d){"
        "    document.getElementById('st').textContent=d.status;"
        "    var p=(d.status==='VERIFYING'||d.status==='APPLYING')?100:d.progress;"
        "    document.getElementById('bar').style.width=p+'%';"
        "    document.getElementById('pct').textContent=p+'%';"
        "    if(d.done){"
        "      clearInterval(tid);"
        "      var m=document.getElementById('msg');"
        "      if(d.status==='SUCCESS'){"
        "        m.innerHTML='<p class=\"done-ok\">&#10003; Update applied! Device will reboot.</p>"
        "<a class=\"btn\" href=\"/status\">&#8592; System Status</a>';"
        "      } else {"
        "        m.innerHTML='<p class=\"done-err\">&#10007; Update failed: '+d.error+'</p>"
        "<a class=\"btn\" href=\"/fw-check\">&#8635; Retry</a>';"
        "      }"
        "    }"
        "  });"
        "},1000);"
        "</script>"
        "</body></html>",
        MHD_HTTP_OK);
}

// ---------------------------------------------------------------------------
// handleConfigUploadGet  –  GET /config-upload
//   Renders a one-time setup page with upload forms for the 5 required files.
// ---------------------------------------------------------------------------
MHD_Result HttpsServer::handleConfigUploadGet(struct MHD_Connection* connection)
{
    // Check which files already exist on the device
    struct FileEntry { const char* label; const char* dest; const char* hint; };
    static const FileEntry FILES[] = {
        { "firmware.conf",      "/etc/iot-gateway/firmware.conf",  "OTA/blockchain settings"         },
        { "blockchain.conf",    "/etc/iot-gateway/blockchain.conf","Ethereum RPC node settings"      },
        { "fw-signer-pubkey.pem","/etc/googlehsmkey/hsm-pubkey.pem","Google HSM RSA/EC public key"   },
        { "system.conf",        "/etc/rauc/system.conf",           "RAUC A/B slot layout"            },
        { "ca.cert.pem",        "/etc/rauc/ca.cert.pem",           "RAUC bundle signing CA cert"     },
    };
    static const int NFILES = 5;

    std::string cards;
    for (int i = 0; i < NFILES; ++i) {
        bool exists = (access(FILES[i].dest, F_OK) == 0);
        std::string status = exists
            ? "<span style='color:#27ae60;'>&#9989; Installed</span>"
            : "<span style='color:#c0392b;'>&#10060; Missing</span>";
        std::string id = "f" + std::to_string(i);
        cards +=
            "<div class='card'>"  
            "<div style='display:flex;justify-content:space-between;align-items:center;'>"  
            "<div><strong>" + std::string(FILES[i].label) + "</strong>"  
            " <span style='color:#888;font-size:0.85em;'>" + FILES[i].hint + "</span><br/>"  
            "<code style='font-size:0.82em;color:#555;'>" + FILES[i].dest + "</code></div>"  
            + status + "</div>"  
            "<div style='margin-top:12px;display:flex;gap:10px;align-items:center;'>"  
            "<input type='file' id='" + id + "' style='flex:1;'/>"  
            "<button onclick=\"uploadCfg('" + id + "','" + std::string(FILES[i].dest) + "','st" + id + "')\""  
            " style='padding:7px 18px;background:#2980b9;color:#fff;border:none;"  
            "border-radius:5px;cursor:pointer;'>Upload</button>"  
            "<span id='st" + id + "' style='font-size:0.9em;'></span>"  
            "</div></div>";
    }

    std::string page =
        "<!DOCTYPE html><html lang='en'>"
        "<head><meta charset='UTF-8'><title>Device Configuration Upload</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;padding:24px;max-width:800px;margin:auto;background:#f8f9fa;}"
        "h1{color:#2c3e50;}p{color:#555;}"
        ".card{background:#fff;border-radius:8px;box-shadow:0 1px 6px rgba(0,0,0,0.10);"
        "padding:18px 22px;margin:14px 0;}"
        ".note{background:#fff3cd;border-left:4px solid #ffc107;padding:10px 14px;"
        "border-radius:4px;margin-bottom:20px;font-size:0.9em;color:#856404;}"
        ".btn-back{display:inline-block;margin-top:18px;padding:9px 22px;background:#3498db;"
        "color:#fff;text-decoration:none;border-radius:5px;font-size:0.95em;}"
        "</style></head><body>"
        "<h1>&#9881; Device Configuration Upload</h1>"
        "<div class='note'>&#8505; Upload these files once after the HTTPS server is up. "
        "Files are written directly to the device filesystem. "
        "Existing files will be overwritten.</div>"
        + cards +
        "<br/><a href='/' class='btn-back'>&#8592; Home</a>"
        "<script>"
        "async function uploadCfg(fid, dest, sid) {"
        "  var fi = document.getElementById(fid);"
        "  if (!fi.files.length) { alert('Select a file first'); return; }"
        "  var st = document.getElementById(sid);"
        "  st.textContent = '\u23f3 Uploading...';"
        "  var text = await fi.files[0].text();"
        "  var body = 'dest=' + encodeURIComponent(dest) + '&content=' + encodeURIComponent(text);"
        "  try {"
        "    var r = await fetch('/config-upload', {method:'POST',"
        "      headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: body});"
        "    if (r.ok) { st.innerHTML = '&#9989; Uploaded'; st.style.color='#27ae60'; }"
        "    else { st.innerHTML = '&#10060; Failed (' + r.status + ')'; st.style.color='#c0392b'; }"
        "  } catch(e) { st.innerHTML = '&#10060; ' + e; st.style.color='#c0392b'; }"
        "}"
        "</script>"
        "</body></html>";

    return sendResponse(connection, page, MHD_HTTP_OK);
}

// ---------------------------------------------------------------------------
// handleConfigUploadPost  –  POST /config-upload
//   Writes the uploaded text to a whitelisted destination path on the device.
// ---------------------------------------------------------------------------
MHD_Result HttpsServer::handleConfigUploadPost(struct MHD_Connection* connection,
                                                ConnectionInfo* con_info,
                                                const char* upload_data,
                                                size_t* upload_data_size)
{
    if (*upload_data_size > 0) {
        con_info->createUploadData();
        con_info->getUploadData()->append(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";

    std::string dest    = getFormField(body_str, "dest");
    std::string content = getFormField(body_str, "content");

    // Strict whitelist — never write to an arbitrary path
    static const char* const ALLOWED[] = {
        "/etc/iot-gateway/firmware.conf",
        "/etc/iot-gateway/blockchain.conf",
        "/etc/googlehsmkey/hsm-pubkey.pem",
        "/etc/rauc/system.conf",
        "/etc/rauc/ca.cert.pem",
        nullptr
    };
    bool allowed = false;
    for (int i = 0; ALLOWED[i]; ++i)
        if (dest == ALLOWED[i]) { allowed = true; break; }

    if (!allowed)
        return sendResponse(connection, "Invalid destination path", MHD_HTTP_BAD_REQUEST);
    if (content.empty())
        return sendResponse(connection, "Empty file content", MHD_HTTP_BAD_REQUEST);

    // Create parent directory hierarchy
    size_t slash = dest.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        std::string dir = dest.substr(0, slash);
        for (size_t i = 1; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/') {
                std::string sub = dir.substr(0, i);
                ::mkdir(sub.c_str(), 0755);  // ignore EEXIST
            }
        }
    }

    std::ofstream ofs(dest, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return sendResponse(connection,
            "Cannot open " + dest + " for writing: " + strerror(errno),
            MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    ofs.write(content.c_str(), static_cast<std::streamsize>(content.size()));
    ofs.close();
    chmod(dest.c_str(), 0640);  // owner rw, group r, world none

    std::cout << "[ConfigUpload] Wrote " << content.size() << " bytes to " << dest << "\n";
    addActivityLog("[CONFIG] Uploaded " + dest.substr(dest.rfind('/') + 1)
                   + " (" + std::to_string(content.size()) + " bytes)");
    return sendResponse(connection, "OK", MHD_HTTP_OK);
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

// Sentinel value stored in con_cls when mTLS enforcement rejected the
// connection. Using a file-scope object guarantees a unique, stable address
// that both the rejection site and the early-exit guard can compare against.
static const int s_mtls_rejected_sentinel = 0;

// Main request handler
// ---------------------------------------------------------------------------
// enforceClientCert
// Application-layer mTLS enforcement.
//
// GnuTLS with MHD_OPTION_HTTPS_MEM_TRUST sends a CertificateRequest during
// the TLS handshake but does NOT abort the handshake when the peer presents
// no certificate or an untrusted one (GNUTLS_CERT_REQUIRE is not set by
// libmicrohttpd). This function retrieves the GnuTLS session from the MHD
// connection, checks whether the peer actually sent a certificate, and then
// verifies that the presented certificate was accepted by the GnuTLS trust
// store (i.e., signed by our Root CA). Returns false (reject) if:
//   - No peer certificate was presented (empty Certificate handshake message)
//   - GnuTLS certificate verification status is non-zero (untrusted CA, etc.)
//
// Localhost exemption: connections from 127.0.0.1 or ::1 are always accepted
// without a client certificate. cloudflared connects from localhost to proxy
// browser requests arriving via the Cloudflare tunnel (raceiotdevice.cc).
// cloudflared does not support presenting a client cert to the origin in its
// config, so we exempt the loopback address. The tunnel transport itself is
// secured end-to-end by Cloudflare's mTLS with its own edge certificates.
// ---------------------------------------------------------------------------
static bool enforceClientCert(struct MHD_Connection* connection) {
    // ── Localhost exemption (cloudflared tunnel) ──────────────────────────
    const union MHD_ConnectionInfo* addr_info =
        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (addr_info && addr_info->client_addr) {
        const struct sockaddr* sa = addr_info->client_addr;
        bool is_loopback = false;
        if (sa->sa_family == AF_INET) {
            const struct sockaddr_in* s4 =
                reinterpret_cast<const struct sockaddr_in*>(sa);
            // 127.0.0.0/8
            is_loopback = ((ntohl(s4->sin_addr.s_addr) >> 24) == 127);
        } else if (sa->sa_family == AF_INET6) {
            const struct sockaddr_in6* s6 =
                reinterpret_cast<const struct sockaddr_in6*>(sa);
            // ::1
            static const uint8_t loopback6[16] =
                {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
            is_loopback = (memcmp(s6->sin6_addr.s6_addr,
                                  loopback6, 16) == 0);
        }
        if (is_loopback) {
            std::cout << "[mTLS] ALLOW: loopback connection (cloudflared tunnel) — "
                         "skipping client cert check\n";
            return true;
        }
    }
    // ─────────────────────────────────────────────────────────────────────

    const union MHD_ConnectionInfo* info =
        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_GNUTLS_SESSION);
    if (!info || !info->tls_session) {
        std::cerr << "[mTLS] Cannot retrieve GnuTLS session from connection\n";
        return false;
    }
    gnutls_session_t session =
        reinterpret_cast<gnutls_session_t>(info->tls_session);

    // Check whether the peer sent any certificate at all
    unsigned int list_size = 0;
    const gnutls_datum_t* cert_list =
        gnutls_certificate_get_peers(session, &list_size);
    if (!cert_list || list_size == 0) {
        std::cerr << "[mTLS] REJECT: No client certificate presented\n";
        return false;
    }

    // Verify that the presented certificate is trusted (signed by Root CA).
    // gnutls_certificate_verify_peers2() re-checks the peer cert chain against
    // the trust store configured via MHD_OPTION_HTTPS_MEM_TRUST.
    unsigned int verify_status = 0;
    int rc = gnutls_certificate_verify_peers2(session, &verify_status);
    if (rc < 0) {
        std::cerr << "[mTLS] REJECT: GnuTLS verify error: "
                  << gnutls_strerror(rc) << "\n";
        return false;
    }
    if (verify_status != 0) {
        gnutls_datum_t out = {};
        gnutls_certificate_verification_status_print(
            verify_status, GNUTLS_CRT_X509, &out, 0);
        std::cerr << "[mTLS] REJECT: Client cert not trusted: "
                  << (out.data ? reinterpret_cast<char*>(out.data) : "unknown")
                  << "\n";
        gnutls_free(out.data);
        return false;
    }

    std::cout << "[mTLS] Client certificate accepted — chain verified OK\n";
    return true;
}

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

        // ── Application-layer mTLS enforcement ──────────────────────────────
        // GnuTLS requests a client cert during the TLS handshake but does NOT
        // reject the connection when the peer sends no cert or an untrusted
        // one. We check here on the first call (before any data is processed)
        // and return 403 immediately for any connection that fails the check.
        HttpsServer* self = static_cast<HttpsServer*>(cls);
        if (self && self->mtls_enabled && !enforceClientCert(connection)) {
            delete con_info;
            // Set con_cls to a non-null sentinel so MHD does not call this
            // handler a second time with con_cls == nullptr for the same
            // connection (which would log the REJECT message twice).
            *con_cls = const_cast<int*>(&s_mtls_rejected_sentinel);
            const char* body =
                "<html><body><h1>403 Forbidden</h1>"
                "<p>A valid client certificate signed by the device Root CA "
                "is required to access this server.</p></body></html>";
            struct MHD_Response* resp = MHD_create_response_from_buffer(
                strlen(body), const_cast<char*>(body), MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/html");
            MHD_Result r = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, resp);
            MHD_destroy_response(resp);
            return r;
        }
        // ────────────────────────────────────────────────────────────────────
        
        *con_cls = con_info;
        return MHD_YES;
    }

    // If con_cls was set to the mTLS-rejected sentinel (non-null but not a
    // ConnectionInfo), MHD may still call us a second time.  Bail out early.
    if (*con_cls == const_cast<int*>(&s_mtls_rejected_sentinel)) {
        return MHD_NO;
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

    // Handle POST /fw-update-trigger
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/fw-update-trigger") == 0) {
        return handleFirmwareTrigger(connection, con_info, upload_data, upload_data_size);
    }

    // Handle POST /config-upload
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/config-upload") == 0) {
        return handleConfigUploadPost(connection, con_info, upload_data, upload_data_size);
    }

    // Handle GET or other methods
    if (std::strcmp(method, "GET") == 0) {
        std::cout << "Handling GET request for URL: " << url << std::endl;
        
        // LED control endpoint
        if (std::strcmp(url, "/startledblink") == 0 || 
            std::strncmp(url, "/startledblink?", 15) == 0) {
            return handleLedControl(connection, url);
        }

        // Firmware update check endpoint
        if (std::strcmp(url, "/fw-check") == 0) {
            return handleFirmwareCheck(connection);
        }

        // Live download/install progress (polled by the progress bar page)
        if (std::strcmp(url, "/fw-progress") == 0) {
            return handleFirmwareProgress(connection);
        }
        
        // Default GET handler
        return handleGetRequest(connection, url);
    }
    
    // Method not allowed
    return sendResponse(connection, "Method not allowed", MHD_HTTP_METHOD_NOT_ALLOWED);
}
