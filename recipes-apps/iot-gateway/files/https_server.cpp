#include "https_server.h"
#include "main.h"
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

// Global buffer for uploaded data
char* uploaded_buffer = nullptr;
size_t uploaded_buffer_size = 0;

// Static user database (username -> password)
std::map<std::string, std::string> HttpsServer::user_db;

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
    : daemon(nullptr), cert_pem(nullptr), key_pem(nullptr), 
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

bool HttpsServer::start(const char* cert_file, const char* key_file) {
    if (running) {
        std::cerr << "Server is already running" << std::endl;
        return false;
    }
    
    // Load certificates
    if (!loadCertificate(cert_file)) {
        std::cerr << "Generate with: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes" << std::endl;
        return false;
    }
    
    if (!loadKey(key_file)) {
        cleanup();
        return false;
    }
    
    // Start HTTPS server
    daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
        port,
        nullptr,
        nullptr,
        &HttpsServer::answerToConnection,
        this,
        MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
        MHD_OPTION_HTTPS_MEM_KEY, key_pem,
        MHD_OPTION_NOTIFY_COMPLETED, HttpsServer::requestCompleted, nullptr,
        MHD_OPTION_END
    );
    
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

// Handle GET request
MHD_Result HttpsServer::handleGetRequest(struct MHD_Connection* connection, const char* url) {

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
        std::string page =
            "<html><body>"
            "<h1>Login</h1>"
            "<form action=\"/login\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Login\"/>"
            "</form>"
            "<p><a href=\"/register\">Don&apos;t have an account? Register</a></p>"
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

    if (user_db.find(username) != user_db.end()) {
        page =
            "<html><body>"
            "<h1>Register</h1>"
            "<p style=\"color:red;\">Username already exists. Please choose another.</p>"
            "<form action=\"/register\" method=\"post\">"
            "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
            "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
            "<input type=\"submit\" value=\"Register\"/>"
            "</form>"
            "<p><a href=\"/login\">Already registered? Log in</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_CONFLICT);
    }

    user_db[username] = password;
    std::cout << "[Register] New user registered: " << username << std::endl;

    page =
        "<html><body>"
        "<h1>Registration Successful!</h1>"
        "<p>Welcome, <strong>" + username + "</strong>! Your account has been created.</p>"
        "<a href=\"/login\"><button>Log In</button></a>"
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

    // Parse form body
    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";

    std::string username = getFormField(body_str, "username");
    std::string password = getFormField(body_str, "password");

    std::string page;
    auto it = user_db.find(username);
    if (it != user_db.end() && it->second == password) {
        std::cout << "[Login] User logged in: " << username << std::endl;
        page =
            "<html><body>"
            "<h1>Login Successful!</h1>"
            "<p>Welcome back, <strong>" + username + "</strong>!</p>"
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

    std::cout << "[Login] Failed login attempt for user: " << username << std::endl;
    page =
        "<html><body>"
        "<h1>Login</h1>"
        "<p style=\"color:red;\">Invalid username or password. Please try again.</p>"
        "<form action=\"/login\" method=\"post\">"
        "<label>Username: <input type=\"text\" name=\"username\" required/></label><br/><br/>"
        "<label>Password: <input type=\"password\" name=\"password\" required/></label><br/><br/>"
        "<input type=\"submit\" value=\"Login\"/>"
        "</form>"
        "<p><a href=\"/register\">Don&apos;t have an account? Register</a></p>"
        "</body></html>";
    return sendResponse(connection, page, MHD_HTTP_UNAUTHORIZED);
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

    UploadData* body = con_info->getUploadData();
    std::string body_str = (body && body->getSize() > 0)
        ? std::string(body->getData(), body->getSize()) : "";

    std::string otp = getFormField(body_str, "otp");

    std::cout << "[OTP] Received OTP input: " << otp << std::endl;

    // Validate: must be exactly 6 digits
    bool valid = (otp.length() == 6);
    for (char c : otp) {
        if (!std::isdigit(static_cast<unsigned char>(c))) { valid = false; break; }
    }

    if (!valid) {
        std::string page =
            "<html><body>"
            "<h1>OTP Verification</h1>"
            "<p style='color:red;'>Invalid OTP. Please enter exactly 6 digits.</p>"
            "<form action='/otp' method='post'>"
            "<label>OTP: <input type='text' name='otp' maxlength='6' "
            "pattern='[0-9]{6}' placeholder='000000' required "
            "style='font-size:1.5em; letter-spacing:0.3em; width:8em;'/></label><br/><br/>"
            "<input type='submit' value='Verify OTP'/>"
            "</form>"
            "<p><a href='/login'>Back to Login</a></p>"
            "</body></html>";
        return sendResponse(connection, page, MHD_HTTP_BAD_REQUEST);
    }

    // OTP verification logic will be added here
    std::string page =
        "<html><body>"
        "<h1>OTP Received</h1>"
        "<p>OTP <strong>" + otp + "</strong> submitted. Verification pending.</p>"
        "</body></html>";
    return sendResponse(connection, page, MHD_HTTP_OK);
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
