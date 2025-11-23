#include "https_server.h"
#include <iostream>
#include <gnutls/gnutls.h>

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

HttpsServer::HttpsServer(int server_port) 
    : daemon(nullptr), cert_pem(nullptr), key_pem(nullptr), 
      port(server_port), running(false) {}

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
    fread(cert_pem, 1, cert_size, cert_fp);
    cert_pem[cert_size] = '\0';
    fclose(cert_fp);
    
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
    fread(key_pem, 1, key_size, key_fp);
    key_pem[key_size] = '\0';
    fclose(key_fp);
    
    return true;
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
    std::cout << "HTTPS server running on https://localhost:" << port << std::endl;
    std::cout << "POST files to https://localhost:" << port << "/upload" << std::endl;
    
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
            
            // You can process the uploaded data here
            // For example, write to file or further processing
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

// Send HTTP response
MHD_Result HttpsServer::sendResponse(struct MHD_Connection* connection, 
                                     const std::string& content, 
                                     int status_code) {
    struct MHD_Response* response = MHD_create_response_from_buffer(
        content.length(),
        const_cast<char*>(content.c_str()),
        MHD_RESPMEM_MUST_COPY
    );
    
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
            con_info->setIsPost(true);
        }
        
        *con_cls = con_info;
        return MHD_YES;
    }
    
    ConnectionInfo* con_info = static_cast<ConnectionInfo*>(*con_cls);
    
    // Handle POST upload
    if (std::strcmp(method, "POST") == 0 && std::strcmp(url, "/upload") == 0) {
        return handlePostUpload(connection, con_info, upload_data, upload_data_size);
    }
    
    // Handle GET or other methods
    if (std::strcmp(method, "GET") == 0) {
        return handleGetRequest(connection, url);
    }
    
    // Method not allowed
    return sendResponse(connection, "Method not allowed", MHD_HTTP_METHOD_NOT_ALLOWED);
}

// ============================================================================
// Main function
// ============================================================================

int main(int argc, char** argv)
{
    const char* cert_file = "server.crt";
    const char* key_file = "server.key";
    
    // Create server instance
    HttpsServer server(8443);
    
    // Start the server
    if (!server.start(cert_file, key_file)) {
        return 1;
    }
    
    std::cout << "Press Enter to stop the server..." << std::endl;
    std::cin.get();
    
    return 0;
}
