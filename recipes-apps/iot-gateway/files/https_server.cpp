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
#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sstream>

// Global buffer for uploaded data
char* uploaded_buffer = nullptr;
size_t uploaded_buffer_size = 0;

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
    std::string page = 
        "<html><body>"
        "<h1>HTTPS Upload Server</h1>"
        "<p>POST data to /upload endpoint</p>"
        "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">"
        "<input type=\"file\" name=\"file\"/>"
        "<input type=\"submit\" value=\"Upload\"/>"
        "</form>"
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

// Helper function to download file using curl
bool HttpsServer::downloadFile(const std::string& url, const std::string& output_path) {
    std::cout << "[OTA Download] Starting download from: " << url << std::endl;
    std::cout << "[OTA Download] Saving to: " << output_path << std::endl;
    
    // Build curl command with progress
    std::string cmd = "curl -k -L -o \"" + output_path + "\" \"" + url + "\" 2>&1";
    
    std::cout << "[OTA Download] Command: " << cmd << std::endl;
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "[OTA Download] ERROR: Failed to execute curl" << std::endl;
        return false;
    }
    
    // Stream curl output to console
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << "[OTA Download] " << buffer;
    }
    
    int status = pclose(pipe);
    
    if (status == 0) {
        std::cout << "[OTA Download] ✓ Download completed successfully" << std::endl;
        return true;
    } else {
        std::cerr << "[OTA Download] ✗ Download failed with exit code: " << status << std::endl;
        return false;
    }
}

// OTA Update Handler
MHD_Result HttpsServer::handleOtaUpdate(struct MHD_Connection* connection, const char* url) {
    std::cout << "\n[OTA Update] ========================================" << std::endl;
    std::cout << "[OTA Update] OTA Update Request Received" << std::endl;
    std::cout << "[OTA Update] ========================================" << std::endl;
    
    // Get URL parameter for image location
    const char* image_url = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "url");
    
    if (!image_url) {
        std::string error_response = R"({
  "status": "error",
  "message": "Missing 'url' parameter",
  "usage": "GET /ota?url=https://server/path/to/image.wic"
})";
        std::cerr << "[OTA Update] ERROR: No URL parameter provided" << std::endl;
        return sendResponse(connection, error_response, MHD_HTTP_BAD_REQUEST);
    }
    
    std::cout << "[OTA Update] Image URL: " << image_url << std::endl;
    
    // Determine current active partition
    std::string output;
    FILE* pipe = popen("/usr/bin/rootfs-manager active 2>&1", "r");
    if (!pipe) {
        std::string error_response = R"({
  "status": "error",
  "message": "Failed to determine active partition"
})";
        return sendResponse(connection, error_response, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output = buffer;
        // Remove trailing newline
        output.erase(output.find_last_not_of(" \n\r\t") + 1);
    }
    pclose(pipe);
    
    std::cout << "[OTA Update] Current active partition: " << output << std::endl;
    
    std::string target_partition;
    std::string target_letter;
    std::string mode;
    
    if (output == "A") {
        // Running from A - Update B (standard A/B update)
        target_partition = "/dev/mmcblk0p3";
        target_letter = "B";
        mode = "Standard A/B Update";
        std::cout << "[OTA Update] Mode: Standard Update" << std::endl;
        std::cout << "[OTA Update] Target: Partition B (inactive)" << std::endl;
    } else if (output == "B") {
        // Running from B (recovery mode) - Can safely update A
        target_partition = "/dev/mmcblk0p2";
        target_letter = "A";
        mode = "Recovery Mode - Repairing Primary Partition";
        std::cout << "[OTA Update] Mode: RECOVERY - Running from backup partition" << std::endl;
        std::cout << "[OTA Update] Target: Partition A (inactive, needs repair)" << std::endl;
    } else {
        std::string error_response = R"({
  "status": "error",
  "message": "Unable to determine partition state"
})";
        return sendResponse(connection, error_response, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    
    std::cout << "[OTA Update] Target partition: " << target_partition << " (" << target_letter << ")" << std::endl;
    
    // Send immediate response that update is starting
    std::string initial_response = R"({
  "status": "accepted",
  "message": "OTA update started",
  "mode": ")" + mode + R"(",
  "current_partition": ")" + output + R"(",
  "target_partition": ")" + target_letter + R"(",
  "device": ")" + target_partition + R"(",
  "note": "Update running in background. System will switch and reboot automatically."
})";
    
    std::cout << "[OTA Update] Starting background update process..." << std::endl;
    
    // Fork to handle update in background
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process - handle the update
        std::cout << "\n[OTA Update] ========================================" << std::endl;
        std::cout << "[OTA Update] Background Update Process Started" << std::endl;
        std::cout << "[OTA Update] PID: " << getpid() << std::endl;
        std::cout << "[OTA Update] ========================================" << std::endl;
        
        // Download image
        std::string temp_image = "/tmp/ota_update.wic";
        std::cout << "[OTA Update] STEP 1/5: Downloading image..." << std::endl;
        
        if (!downloadFile(image_url, temp_image)) {
            std::cerr << "[OTA Update] FAILED: Download error" << std::endl;
            unlink(temp_image.c_str());
            exit(1);
        }
        
        // Verify downloaded file exists and has size
        struct stat st;
        if (stat(temp_image.c_str(), &st) != 0 || st.st_size == 0) {
            std::cerr << "[OTA Update] FAILED: Downloaded file is invalid or empty" << std::endl;
            unlink(temp_image.c_str());
            exit(1);
        }
        
        std::cout << "[OTA Update] ✓ Downloaded " << st.st_size << " bytes" << std::endl;
        
        // Check if it's compressed
        bool is_compressed = (std::string(image_url).find(".bz2") != std::string::npos);
        std::string flash_image = temp_image;
        
        if (is_compressed) {
            std::cout << "[OTA Update] STEP 2/5: Decompressing image..." << std::endl;
            std::string decompress_cmd = "bunzip2 -f \"" + temp_image + "\" 2>&1";
            std::cout << "[OTA Update] Command: " << decompress_cmd << std::endl;
            int result = system(decompress_cmd.c_str());
            if (result != 0) {
                std::cerr << "[OTA Update] FAILED: Decompression error" << std::endl;
                exit(1);
            }
            // After decompression, file loses .bz2 extension
            flash_image = temp_image.substr(0, temp_image.length() - 4);
            std::cout << "[OTA Update] ✓ Decompressed to: " << flash_image << std::endl;
        } else {
            std::cout << "[OTA Update] STEP 2/5: Skipped (image not compressed)" << std::endl;
        }
        
        // Remount target partition as read-write if needed
        std::cout << "[OTA Update] STEP 3/5: Preparing target partition..." << std::endl;
        std::string remount_cmd = "mount -o remount,rw " + target_partition + " 2>&1 || true";
        system(remount_cmd.c_str());
        
        // Unmount if mounted
        std::string unmount_cmd = "umount " + target_partition + " 2>&1 || true";
        system(unmount_cmd.c_str());
        std::cout << "[OTA Update] ✓ Target partition prepared" << std::endl;
        
        // Flash the image
        std::cout << "[OTA Update] STEP 4/5: Flashing image to " << target_partition << "..." << std::endl;
        std::string flash_cmd = "dd if=\"" + flash_image + "\" of=" + target_partition + " bs=4M status=progress 2>&1";
        std::cout << "[OTA Update] Command: " << flash_cmd << std::endl;
        std::cout << "[OTA Update] This may take several minutes..." << std::endl;
        
        FILE* dd_pipe = popen(flash_cmd.c_str(), "r");
        if (dd_pipe) {
            char dd_buffer[256];
            while (fgets(dd_buffer, sizeof(dd_buffer), dd_pipe) != nullptr) {
                std::cout << "[OTA Update] " << dd_buffer;
            }
            int dd_result = pclose(dd_pipe);
            if (dd_result != 0) {
                std::cerr << "[OTA Update] FAILED: Flash error (dd exit code: " << dd_result << ")" << std::endl;
                unlink(flash_image.c_str());
                exit(1);
            }
        }
        
        std::cout << "[OTA Update] ✓ Flashing completed" << std::endl;
        
        // Sync to ensure data is written
        std::cout << "[OTA Update] STEP 5/5: Syncing filesystem..." << std::endl;
        sync();
        std::cout << "[OTA Update] ✓ Sync completed" << std::endl;
        
        // Cleanup
        unlink(flash_image.c_str());
        
        // Verify the flashed partition
        std::cout << "[OTA Update] Verifying flashed partition..." << std::endl;
        std::string verify_cmd = "/usr/bin/rootfs-manager verify 2>&1";
        system(verify_cmd.c_str());
        
        std::cout << "\n[OTA Update] ========================================" << std::endl;
        std::cout << "[OTA Update] UPDATE COMPLETED SUCCESSFULLY" << std::endl;
        std::cout << "[OTA Update] ========================================" << std::endl;
        std::cout << "[OTA Update] Updated partition: " << target_letter << " (" << target_partition << ")" << std::endl;
        std::cout << "[OTA Update] Switching boot partition to: " << target_letter << std::endl;
        std::cout << "[OTA Update] ========================================" << std::endl;
        
        // Switch boot partition to the newly updated one
        std::string switch_cmd = "/usr/bin/rootfs-manager switch " + target_letter + " 2>&1";
        std::cout << "[OTA Update] Executing: " << switch_cmd << std::endl;
        system(switch_cmd.c_str());
        
        std::cout << "[OTA Update] Boot partition switched successfully" << std::endl;
        std::cout << "[OTA Update] System will reboot in 10 seconds..." << std::endl;
        
        // Give time to see the message
        sleep(10);
        
        // Reboot to apply the update
        std::cout << "[OTA Update] Rebooting now..." << std::endl;
        sync();
        system("reboot");
        
        exit(0);
    } else if (pid > 0) {
        // Parent process - return response immediately
        std::cout << "[OTA Update] Update process forked with PID: " << pid << std::endl;
        std::cout << "[OTA Update] Returning response to client..." << std::endl;
        return sendResponse(connection, initial_response, MHD_HTTP_ACCEPTED);
    } else {
        // Fork failed
        std::string error_response = R"({
  "status": "error",
  "message": "Failed to start background update process"
})";
        return sendResponse(connection, error_response, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
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
        //Handling POST upload request... Print to linux terminal
        std::cout << "Handling POST upload request..." << std::endl;
        return handlePostUpload(connection, con_info, upload_data, upload_data_size);
    }
    
    // Handle GET or other methods
    if (std::strcmp(method, "GET") == 0) {
        std::cout << "Handling GET request for URL: " << url << std::endl;
        
        // OTA update endpoint
        if (std::strcmp(url, "/ota") == 0 || 
            std::strncmp(url, "/ota?", 5) == 0) {
            return handleOtaUpdate(connection, url);
        }
        
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
