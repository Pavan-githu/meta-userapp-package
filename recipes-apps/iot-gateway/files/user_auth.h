#ifndef USER_AUTH_H
#define USER_AUTH_H

#include <string>
#include <vector>
#include <ctime>
#include <pthread.h>

// -------------------------------------------------------------------------
// UserRecord – one entry in the persistent user registry
// -------------------------------------------------------------------------
struct UserRecord {
    std::string username;   // unique, alphanumeric + '_', max 64 chars
    std::string salt_hex;   // 32 hex chars  (16 raw bytes)
    std::string hash_hex;   // 64 hex chars  (32 raw bytes, PBKDF2-HMAC-SHA256)
    std::string role;       // "admin" | "user"
    std::time_t created_at; // Unix timestamp
};

// -------------------------------------------------------------------------
// UserAuth – user registry with salted-hash password storage
//
// Registry file format (one line per user, colon-separated):
//   username:salt_hex:hash_hex:role:created_at_unix
//
// Passwords are hashed with PBKDF2-HMAC-SHA256 using a per-user 128-bit
// salt generated via OpenSSL RAND_bytes.  Hash comparison is done with
// CRYPTO_memcmp to prevent timing side-channels.
// -------------------------------------------------------------------------
class UserAuth {
public:
    // Tuneable constants
    static const int SALT_BYTES        = 16;       // 128-bit salt
    static const int HASH_BYTES        = 32;       // 256-bit derived key
    static const int PBKDF2_ITERATIONS = 100000;   // OWASP minimum for SHA-256
    static const int MAX_USERNAME_LEN  = 64;
    static const int MIN_PASSWORD_LEN  = 8;

    // Constructor – registry_file will be created if it does not exist.
    // Default path stores alongside TLS certificates.
    explicit UserAuth(const std::string& registry_file = "/etc/iot-gateway/users.db");
    ~UserAuth();

    // Prevent copying (registry mutex is not copyable)
    UserAuth(const UserAuth&)            = delete;
    UserAuth& operator=(const UserAuth&) = delete;

    // -----------------------------------------------------------------
    // User management
    // -----------------------------------------------------------------

    // Register a new user.  Returns false if the username already exists,
    // if the password is too short, or if username contains invalid chars.
    bool registerUser(const std::string& username,
                      const std::string& password,
                      const std::string& role = "user");

    // Verify username/password against the stored hash.
    // Returns true only when both username exists and hash matches.
    bool authenticate(const std::string& username,
                      const std::string& password);

    // Change password – requires the current password to succeed.
    bool changePassword(const std::string& username,
                        const std::string& old_password,
                        const std::string& new_password);

    // Remove a user from the registry.  Returns false if not found.
    bool removeUser(const std::string& username);

    // -----------------------------------------------------------------
    // Registry inspection (read-only)
    // -----------------------------------------------------------------

    bool   userExists(const std::string& username) const;
    bool   getUserRecord(const std::string& username, UserRecord& out) const;
    size_t getUserCount() const;

    // Returns sorted list of all registered usernames.
    std::vector<std::string> listUsers() const;

private:
    std::string              registry_path_;
    std::vector<UserRecord>  registry_;
    mutable pthread_mutex_t  mutex_;

    // Persistence
    bool loadRegistry();
    bool saveRegistry() const;
    bool ensureRegistryDir() const;

    // Crypto helpers
    bool generateSalt(std::string& salt_hex) const;
    bool hashPassword(const std::string& password,
                      const std::string& salt_hex,
                      std::string& hash_hex) const;
    bool verifyPassword(const std::string& password,
                        const std::string& salt_hex,
                        const std::string& stored_hash_hex) const;

    // Encoding helpers
    static std::string bytesToHex(const unsigned char* data, size_t len);
    static bool        hexToBytes(const std::string& hex,
                                  unsigned char* out,
                                  size_t out_len);

    // Validation helpers
    static bool isValidUsername(const std::string& username);
    static bool isValidRole(const std::string& role);

    // Parse / serialise a single registry line
    static bool        parseRecord(const std::string& line, UserRecord& rec);
    static std::string serialiseRecord(const UserRecord& rec);
};

#endif // USER_AUTH_H
