#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#include <string>
#include <cstring>
#include <microhttpd.h>

// Class to hold uploaded data with dynamic memory management
class UploadData {
private:
    char* data;
    size_t size;
    size_t capacity;

public:
    UploadData();
    ~UploadData();
    
    // Prevent copying
    UploadData(const UploadData&) = delete;
    UploadData& operator=(const UploadData&) = delete;
    
    // Append data to buffer, resizing if necessary
    void append(const char* new_data, size_t new_size);
    
    // Getters
    char* getData() const { return data; }
    size_t getSize() const { return size; }
    size_t getCapacity() const { return capacity; }
};

// Class to manage connection-specific information
class ConnectionInfo {
private:
    UploadData* upload_data;
    bool is_post;

public:
    ConnectionInfo();
    ~ConnectionInfo();
    
    // Prevent copying
    ConnectionInfo(const ConnectionInfo&) = delete;
    ConnectionInfo& operator=(const ConnectionInfo&) = delete;
    
    // Methods
    void setIsPost(bool post) { is_post = post; }
    bool getIsPost() const { return is_post; }
    
    UploadData* getUploadData() { return upload_data; }
    void createUploadData();
};

// HTTPS Server class
class HttpsServer {
private:
    struct MHD_Daemon* daemon;
    char* cert_pem;
    char* key_pem;
    int port;
    bool running = false;
    std::string bind_address;
    
    // Private methods
    bool loadCertificate(const char* cert_file);
    bool loadKey(const char* key_file);
    void cleanup();
    std::string getLocalIPAddress();

public:
    HttpsServer(int server_port = 8443, const std::string& bind_addr = "0.0.0.0");
    ~HttpsServer();
    
    // Prevent copying
    HttpsServer(const HttpsServer&) = delete;
    HttpsServer& operator=(const HttpsServer&) = delete;
    
    // Server control methods
    bool start(const char* cert_file, const char* key_file);
    void stop();
    bool isRunning() const { return running; }
    int getPort() const { return port; }
    
    // Static callback functions for libmicrohttpd
    static MHD_Result answerToConnection(void* cls, struct MHD_Connection* connection,
                                        const char* url, const char* method,
                                        const char* version, const char* upload_data,
                                        size_t* upload_data_size, void** con_cls);
    
    static void requestCompleted(void* cls, struct MHD_Connection* connection,
                                void** con_cls, enum MHD_RequestTerminationCode toe);
    
    static MHD_Result iteratePost(void* coninfo_cls, enum MHD_ValueKind kind, 
                                 const char* key, const char* filename, 
                                 const char* content_type, const char* transfer_encoding,
                                 const char* data, uint64_t off, size_t size);
    
private:
    // Handler methods
    static MHD_Result handlePostUpload(struct MHD_Connection* connection, 
                                      ConnectionInfo* con_info,
                                      const char* upload_data, size_t* upload_data_size);
    
    static MHD_Result handleGetRequest(struct MHD_Connection* connection, const char* url);
    
    static MHD_Result sendResponse(struct MHD_Connection* connection, 
                                   const std::string& content, 
                                   int status_code);
};

#endif // HTTPS_SERVER_H
