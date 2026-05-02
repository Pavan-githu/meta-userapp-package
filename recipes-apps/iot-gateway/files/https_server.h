#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#include <string>
#include <cstring>
#include <ctime>
#include <map>
#include <pthread.h>
#include <microhttpd.h>

// Forward declarations – avoid pulling heavy headers into this header
class UserAuth;
class BlockchainLogger;

// ---------------------------------------------------------------------------
// PendingOTP – in-memory state for the OTP verification phase
//
// Created when a user successfully passes the password check and destroyed
// once the OTP is verified (or expires after OTP_SESSION_TTL seconds).
// The session_id is sent as a Secure HttpOnly cookie and used as the map key.
// ---------------------------------------------------------------------------
struct PendingOTP {
    std::string username;       // who is authenticating
    std::string totp_secret;    // base32 TOTP secret for this user
    std::string session_id;     // 64-hex-char (32-byte) random session token
    std::time_t expires_at;     // Unix timestamp – expires after OTP_SESSION_TTL s
    int         local_fails;    // local fail counter (blockchain is authoritative)
};

// How long (seconds) the OTP phase stays open before it expires
static const int OTP_SESSION_TTL = 120;
// Max local OTP failures before refusing to check blockchain (fast path)
static const int MAX_LOCAL_OTP_FAILS = 3;

// Class to hold uploaded data with dynamic memory management
class UploadData {
private:
    char* data;
    size_t size;
    size_t capacity;
    char* uploaded_buffer;

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

    // ------------------------------------------------------------------
    // MFA initialisation  (call before start())
    // ------------------------------------------------------------------
    // Wire the UserAuth registry and BlockchainLogger into the server.
    // Both pointers must remain valid for the server’s lifetime.
    static void initMFA(UserAuth* user_auth, BlockchainLogger* blockchain);

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
    
    static MHD_Result handleLedControl(struct MHD_Connection* connection, const char* url);

    static MHD_Result handleRegisterPost(struct MHD_Connection* connection,
                                         ConnectionInfo* con_info,
                                         const char* upload_data,
                                         size_t* upload_data_size);

    static MHD_Result handleLoginPost(struct MHD_Connection* connection,
                                      ConnectionInfo* con_info,
                                      const char* upload_data,
                                      size_t* upload_data_size);

    static MHD_Result handleOtpPost(struct MHD_Connection* connection,
                                    ConnectionInfo* con_info,
                                    const char* upload_data,
                                    size_t* upload_data_size);

    static MHD_Result sendResponse(struct MHD_Connection* connection, 
                                   const std::string& content, 
                                   int status_code);

    // ------------------------------------------------------------------
    // Static MFA state  (protected by s_session_mutex)
    // ------------------------------------------------------------------
    static UserAuth*                          s_user_auth;
    static BlockchainLogger*                  s_blockchain;
    static std::map<std::string, PendingOTP>  s_sessions;     // key = session_id
    static pthread_mutex_t                    s_session_mutex;
    static std::map<std::string, std::string> user_db;        // legacy fallback
};

#endif // HTTPS_SERVER_H
