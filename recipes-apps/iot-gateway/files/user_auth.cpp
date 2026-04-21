#include "user_auth.h"

#include <openssl/evp.h>    // EVP_sha256, PKCS5_PBKDF2_HMAC
#include <openssl/rand.h>   // RAND_bytes
#include <openssl/crypto.h> // CRYPTO_memcmp

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cerrno>
#include <sys/stat.h>   // mkdir, chmod
#include <sys/types.h>

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

UserAuth::UserAuth(const std::string& registry_file)
    : registry_path_(registry_file)
{
    pthread_mutex_init(&mutex_, nullptr);
    ensureRegistryDir();
    loadRegistry();
}

UserAuth::~UserAuth()
{
    pthread_mutex_destroy(&mutex_);
}

// ---------------------------------------------------------------------------
// Public – user management
// ---------------------------------------------------------------------------

bool UserAuth::registerUser(const std::string& username,
                            const std::string& password,
                            const std::string& role)
{
    if (!isValidUsername(username)) {
        std::cerr << "[UserAuth] registerUser: invalid username '" << username << "'\n";
        return false;
    }
    if (!isValidRole(role)) {
        std::cerr << "[UserAuth] registerUser: invalid role '" << role << "'\n";
        return false;
    }
    if (static_cast<int>(password.size()) < MIN_PASSWORD_LEN) {
        std::cerr << "[UserAuth] registerUser: password too short (min "
                  << MIN_PASSWORD_LEN << " chars)\n";
        return false;
    }

    pthread_mutex_lock(&mutex_);

    // Reject duplicate usernames
    for (const auto& rec : registry_) {
        if (rec.username == username) {
            pthread_mutex_unlock(&mutex_);
            std::cerr << "[UserAuth] registerUser: username '" << username
                      << "' already exists\n";
            return false;
        }
    }

    std::string salt_hex, hash_hex;
    if (!generateSalt(salt_hex) || !hashPassword(password, salt_hex, hash_hex)) {
        pthread_mutex_unlock(&mutex_);
        std::cerr << "[UserAuth] registerUser: crypto failure\n";
        return false;
    }

    UserRecord rec;
    rec.username   = username;
    rec.salt_hex   = salt_hex;
    rec.hash_hex   = hash_hex;
    rec.role       = role;
    rec.created_at = std::time(nullptr);

    registry_.push_back(rec);
    bool ok = saveRegistry();

    pthread_mutex_unlock(&mutex_);

    if (ok) {
        std::cout << "[UserAuth] Registered user '" << username
                  << "' (role=" << role << ")\n";
    }
    return ok;
}

bool UserAuth::authenticate(const std::string& username,
                            const std::string& password)
{
    pthread_mutex_lock(&mutex_);

    for (const auto& rec : registry_) {
        if (rec.username == username) {
            bool ok = verifyPassword(password, rec.salt_hex, rec.hash_hex);
            pthread_mutex_unlock(&mutex_);
            if (ok) {
                std::cout << "[UserAuth] Authentication SUCCESS for '"
                          << username << "'\n";
            } else {
                std::cerr << "[UserAuth] Authentication FAILED for '"
                          << username << "'\n";
            }
            return ok;
        }
    }

    pthread_mutex_unlock(&mutex_);
    std::cerr << "[UserAuth] Authentication FAILED: unknown user '"
              << username << "'\n";
    return false;
}

bool UserAuth::changePassword(const std::string& username,
                              const std::string& old_password,
                              const std::string& new_password)
{
    if (static_cast<int>(new_password.size()) < MIN_PASSWORD_LEN) {
        std::cerr << "[UserAuth] changePassword: new password too short\n";
        return false;
    }

    pthread_mutex_lock(&mutex_);

    for (auto& rec : registry_) {
        if (rec.username == username) {
            if (!verifyPassword(old_password, rec.salt_hex, rec.hash_hex)) {
                pthread_mutex_unlock(&mutex_);
                std::cerr << "[UserAuth] changePassword: wrong current password\n";
                return false;
            }

            std::string new_salt, new_hash;
            if (!generateSalt(new_salt) || !hashPassword(new_password, new_salt, new_hash)) {
                pthread_mutex_unlock(&mutex_);
                std::cerr << "[UserAuth] changePassword: crypto failure\n";
                return false;
            }

            rec.salt_hex = new_salt;
            rec.hash_hex = new_hash;
            bool ok = saveRegistry();
            pthread_mutex_unlock(&mutex_);

            if (ok) {
                std::cout << "[UserAuth] Password changed for '" << username << "'\n";
            }
            return ok;
        }
    }

    pthread_mutex_unlock(&mutex_);
    std::cerr << "[UserAuth] changePassword: user '" << username << "' not found\n";
    return false;
}

bool UserAuth::removeUser(const std::string& username)
{
    pthread_mutex_lock(&mutex_);

    for (auto it = registry_.begin(); it != registry_.end(); ++it) {
        if (it->username == username) {
            registry_.erase(it);
            bool ok = saveRegistry();
            pthread_mutex_unlock(&mutex_);
            if (ok) {
                std::cout << "[UserAuth] Removed user '" << username << "'\n";
            }
            return ok;
        }
    }

    pthread_mutex_unlock(&mutex_);
    std::cerr << "[UserAuth] removeUser: user '" << username << "' not found\n";
    return false;
}

// ---------------------------------------------------------------------------
// Public – read-only inspection
// ---------------------------------------------------------------------------

bool UserAuth::userExists(const std::string& username) const
{
    pthread_mutex_lock(&mutex_);
    for (const auto& rec : registry_) {
        if (rec.username == username) {
            pthread_mutex_unlock(&mutex_);
            return true;
        }
    }
    pthread_mutex_unlock(&mutex_);
    return false;
}

bool UserAuth::getUserRecord(const std::string& username, UserRecord& out) const
{
    pthread_mutex_lock(&mutex_);
    for (const auto& rec : registry_) {
        if (rec.username == username) {
            out = rec;
            pthread_mutex_unlock(&mutex_);
            return true;
        }
    }
    pthread_mutex_unlock(&mutex_);
    return false;
}

size_t UserAuth::getUserCount() const
{
    pthread_mutex_lock(&mutex_);
    size_t n = registry_.size();
    pthread_mutex_unlock(&mutex_);
    return n;
}

std::vector<std::string> UserAuth::listUsers() const
{
    pthread_mutex_lock(&mutex_);
    std::vector<std::string> names;
    names.reserve(registry_.size());
    for (const auto& rec : registry_) {
        names.push_back(rec.username);
    }
    pthread_mutex_unlock(&mutex_);
    std::sort(names.begin(), names.end());
    return names;
}

// ---------------------------------------------------------------------------
// Private – persistence
// ---------------------------------------------------------------------------

bool UserAuth::ensureRegistryDir() const
{
    // Extract directory component from registry_path_
    size_t slash = registry_path_.rfind('/');
    if (slash == std::string::npos) {
        return true; // relative path, current directory
    }

    std::string dir = registry_path_.substr(0, slash);
    if (dir.empty()) {
        return true;
    }

    // Create directory tree component by component
    std::string path;
    for (size_t i = 0; i < dir.size(); ++i) {
        path += dir[i];
        if (dir[i] == '/' || i + 1 == dir.size()) {
            if (!path.empty() && path != "/") {
                mkdir(path.c_str(), 0700); // ignore EEXIST
            }
        }
    }
    return true;
}

bool UserAuth::loadRegistry()
{
    // registry_ must already be locked by caller OR we are in the constructor
    registry_.clear();

    std::ifstream ifs(registry_path_);
    if (!ifs.is_open()) {
        // File does not exist yet – empty registry, will be created on first save
        return true;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        UserRecord rec;
        if (parseRecord(line, rec)) {
            registry_.push_back(rec);
        } else {
            std::cerr << "[UserAuth] loadRegistry: skipping malformed line\n";
        }
    }

    std::cout << "[UserAuth] Loaded " << registry_.size()
              << " user(s) from " << registry_path_ << "\n";
    return true;
}

bool UserAuth::saveRegistry() const
{
    // Write to a temp file then atomically rename to prevent partial writes
    std::string tmp_path = registry_path_ + ".tmp";

    std::ofstream ofs(tmp_path);
    if (!ofs.is_open()) {
        std::cerr << "[UserAuth] saveRegistry: cannot open '" << tmp_path
                  << "': " << strerror(errno) << "\n";
        return false;
    }

    ofs << "# IoT Gateway user registry – do not edit manually\n";
    for (const auto& rec : registry_) {
        ofs << serialiseRecord(rec) << "\n";
    }
    ofs.close();

    // Restrict permissions before making the file visible
    chmod(tmp_path.c_str(), 0600);

    if (rename(tmp_path.c_str(), registry_path_.c_str()) != 0) {
        std::cerr << "[UserAuth] saveRegistry: rename failed: "
                  << strerror(errno) << "\n";
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Private – crypto
// ---------------------------------------------------------------------------

bool UserAuth::generateSalt(std::string& salt_hex) const
{
    unsigned char buf[SALT_BYTES];
    if (RAND_bytes(buf, SALT_BYTES) != 1) {
        std::cerr << "[UserAuth] generateSalt: RAND_bytes failed\n";
        return false;
    }
    salt_hex = bytesToHex(buf, SALT_BYTES);
    return true;
}

bool UserAuth::hashPassword(const std::string& password,
                            const std::string& salt_hex,
                            std::string& hash_hex) const
{
    unsigned char salt[SALT_BYTES];
    if (!hexToBytes(salt_hex, salt, SALT_BYTES)) {
        return false;
    }

    unsigned char derived[HASH_BYTES];
    int rc = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt,
        SALT_BYTES,
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        HASH_BYTES,
        derived);

    if (rc != 1) {
        std::cerr << "[UserAuth] hashPassword: PBKDF2 failed\n";
        return false;
    }

    hash_hex = bytesToHex(derived, HASH_BYTES);

    // Zero sensitive material
    OPENSSL_cleanse(derived, HASH_BYTES);
    return true;
}

bool UserAuth::verifyPassword(const std::string& password,
                              const std::string& salt_hex,
                              const std::string& stored_hash_hex) const
{
    std::string candidate_hash;
    if (!hashPassword(password, salt_hex, candidate_hash)) {
        return false;
    }

    // Constant-time comparison to prevent timing side-channel attacks
    if (candidate_hash.size() != stored_hash_hex.size()) {
        return false;
    }
    return CRYPTO_memcmp(candidate_hash.c_str(),
                         stored_hash_hex.c_str(),
                         candidate_hash.size()) == 0;
}

// ---------------------------------------------------------------------------
// Private – encoding helpers
// ---------------------------------------------------------------------------

std::string UserAuth::bytesToHex(const unsigned char* data, size_t len)
{
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex_chars[(data[i] >> 4) & 0x0F];
        out += hex_chars[ data[i]       & 0x0F];
    }
    return out;
}

bool UserAuth::hexToBytes(const std::string& hex,
                          unsigned char* out,
                          size_t out_len)
{
    if (hex.size() != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int hi, lo;
        char c_hi = hex[2 * i];
        char c_lo = hex[2 * i + 1];

        if      (c_hi >= '0' && c_hi <= '9') hi = static_cast<unsigned int>(c_hi - '0');
        else if (c_hi >= 'a' && c_hi <= 'f') hi = static_cast<unsigned int>(c_hi - 'a' + 10);
        else if (c_hi >= 'A' && c_hi <= 'F') hi = static_cast<unsigned int>(c_hi - 'A' + 10);
        else return false;

        if      (c_lo >= '0' && c_lo <= '9') lo = static_cast<unsigned int>(c_lo - '0');
        else if (c_lo >= 'a' && c_lo <= 'f') lo = static_cast<unsigned int>(c_lo - 'a' + 10);
        else if (c_lo >= 'A' && c_lo <= 'F') lo = static_cast<unsigned int>(c_lo - 'A' + 10);
        else return false;

        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Private – validation helpers
// ---------------------------------------------------------------------------

bool UserAuth::isValidUsername(const std::string& username)
{
    if (username.empty() || static_cast<int>(username.size()) > MAX_USERNAME_LEN) {
        return false;
    }
    for (char c : username) {
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
               c == '_' || c == '-')) {
            return false;
        }
    }
    // Colon is the field delimiter – must never appear in a username
    return username.find(':') == std::string::npos;
}

bool UserAuth::isValidRole(const std::string& role)
{
    return role == "admin" || role == "user";
}

// ---------------------------------------------------------------------------
// Private – record serialisation / parsing
// ---------------------------------------------------------------------------

// Format:  username:salt_hex:hash_hex:role:created_at_unix
std::string UserAuth::serialiseRecord(const UserRecord& rec)
{
    std::ostringstream oss;
    oss << rec.username    << ':'
        << rec.salt_hex    << ':'
        << rec.hash_hex    << ':'
        << rec.role        << ':'
        << static_cast<long long>(rec.created_at);
    return oss.str();
}

bool UserAuth::parseRecord(const std::string& line, UserRecord& rec)
{
    // Split on ':'
    std::vector<std::string> fields;
    std::istringstream iss(line);
    std::string token;
    while (std::getline(iss, token, ':')) {
        fields.push_back(token);
    }

    if (fields.size() != 5) {
        return false;
    }

    // Basic sanity checks on sizes
    if (fields[1].size() != static_cast<size_t>(SALT_BYTES * 2)) return false;
    if (fields[2].size() != static_cast<size_t>(HASH_BYTES * 2)) return false;

    rec.username   = fields[0];
    rec.salt_hex   = fields[1];
    rec.hash_hex   = fields[2];
    rec.role       = fields[3];

    try {
        rec.created_at = static_cast<std::time_t>(std::stoll(fields[4]));
    } catch (...) {
        return false;
    }

    return isValidUsername(rec.username) && isValidRole(rec.role);
}
