#include "firmwareupdate.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// ---------------------------------------------------------------------------
// firmwareStatusLabel
// ---------------------------------------------------------------------------
const char* firmwareStatusLabel(FirmwareUpdateStatus s)
{
    switch (s) {
        case FirmwareUpdateStatus::IDLE:        return "IDLE";
        case FirmwareUpdateStatus::DOWNLOADING: return "DOWNLOADING";
        case FirmwareUpdateStatus::VERIFYING:   return "VERIFYING";
        case FirmwareUpdateStatus::APPLYING:    return "APPLYING";
        case FirmwareUpdateStatus::SUCCESS:     return "SUCCESS";
        case FirmwareUpdateStatus::FAILED:      return "FAILED";
        default:                                return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
FirmwareUpdateManager::FirmwareUpdateManager(const std::string& current_binary_path,
                                             const std::string& current_version)
    : m_current_binary_path(current_binary_path)
    , m_current_version(current_version)
    , m_thread_running(false)
    , m_cancel_requested(false)
    , m_status(FirmwareUpdateStatus::IDLE)
{
    pthread_mutex_init(&m_mutex, nullptr);
    std::cout << "[FirmwareUpdate] Manager initialized. Current version: "
              << current_version << std::endl;
}

FirmwareUpdateManager::~FirmwareUpdateManager()
{
    // If a thread is still running, signal cancel and join
    if (m_thread_running) {
        cancel();
        pthread_join(m_thread, nullptr);
    }
    pthread_mutex_destroy(&m_mutex);
}

// ---------------------------------------------------------------------------
// startUpdate  –  validate config and launch the background thread
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::startUpdate(const FirmwareUpdateConfig& config)
{
    // Reject if already running
    if (m_thread_running ||
        m_status.load() == FirmwareUpdateStatus::DOWNLOADING ||
        m_status.load() == FirmwareUpdateStatus::VERIFYING   ||
        m_status.load() == FirmwareUpdateStatus::APPLYING) {
        setError("Update already in progress");
        return false;
    }

    // Basic config validation
    if (!isHttpsUrl(config.url)) {
        setError("Firmware URL must use HTTPS (plain HTTP is rejected for security)");
        return false;
    }
    if (config.expected_sha256.size() != 64) {
        setError("expected_sha256 must be a 64-character hex string");
        return false;
    }
    if (config.target_path.empty() || config.staging_path.empty()) {
        setError("target_path and staging_path must not be empty");
        return false;
    }
    if (config.ca_cert_path.empty()) {
        setError("ca_cert_path must be provided for TLS peer verification");
        return false;
    }

    // Version check: skip if up-to-date
    if (!config.version.empty()) {
        int cmp = compareSemver(config.version, m_current_version);
        if (cmp == 0) {
            setError("Firmware is already at version " + config.version);
            return false;
        }
        if (cmp < 0 && cmp != -2) {
            setError("Refusing downgrade from " + m_current_version +
                     " to " + config.version);
            return false;
        }
    }

    m_active_config     = config;
    m_cancel_requested  = false;
    m_status.store(FirmwareUpdateStatus::DOWNLOADING);

    if (pthread_create(&m_thread, nullptr, updateThreadEntry, this) != 0) {
        m_status.store(FirmwareUpdateStatus::FAILED);
        setError(std::string("pthread_create failed: ") + strerror(errno));
        return false;
    }

    m_thread_running = true;
    std::cout << "[FirmwareUpdate] Background update thread started. Target version: "
              << config.version << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// updateThreadEntry  –  runs download → verify → apply in sequence
// ---------------------------------------------------------------------------
void* FirmwareUpdateManager::updateThreadEntry(void* arg)
{
    FirmwareUpdateManager* self = static_cast<FirmwareUpdateManager*>(arg);
    const FirmwareUpdateConfig& cfg = self->m_active_config;

    auto fail = [&](const std::string& msg) {
        self->setError(msg);
        self->m_status.store(FirmwareUpdateStatus::FAILED);
        // Remove staging file if it exists
        if (!cfg.staging_path.empty())
            std::remove(cfg.staging_path.c_str());
        self->m_thread_running = false;
        pthread_exit(nullptr);
    };

    // Step 1: Download
    if (!self->downloadFirmware(cfg))
        fail(self->getLastError());

    if (self->m_cancel_requested.load()) {
        fail("Update cancelled by caller");
    }

    // Step 2: Verify
    self->m_status.store(FirmwareUpdateStatus::VERIFYING);
    if (!self->verifySha256(cfg))
        fail(self->getLastError());

    // Step 3: Apply
    self->m_status.store(FirmwareUpdateStatus::APPLYING);
    if (!self->applyUpdate(cfg))
        fail(self->getLastError());

    self->m_current_version = cfg.version;
    self->m_status.store(FirmwareUpdateStatus::SUCCESS);
    std::cout << "[FirmwareUpdate] Update to " << cfg.version
              << " applied successfully. Please reboot." << std::endl;

    self->m_thread_running = false;
    pthread_exit(nullptr);
    return nullptr;
}

// ---------------------------------------------------------------------------
// downloadFirmware  –  HTTPS download via libcurl into staging_path
// ---------------------------------------------------------------------------

// CURL write callback: appends received bytes to the open FILE*
size_t FirmwareUpdateManager::curlWriteCallback(void* ptr, size_t size,
                                                size_t nmemb, void* userdata)
{
    FILE* fp = static_cast<FILE*>(userdata);
    return std::fwrite(ptr, size, nmemb, fp);
}

bool FirmwareUpdateManager::downloadFirmware(const FirmwareUpdateConfig& cfg)
{
    std::cout << "[FirmwareUpdate] Downloading from " << cfg.url << std::endl;

    FILE* fp = std::fopen(cfg.staging_path.c_str(), "wb");
    if (!fp) {
        setError(std::string("Cannot open staging file for writing: ") +
                 cfg.staging_path + " (" + strerror(errno) + ")");
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::fclose(fp);
        setError("curl_easy_init() failed");
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL,            cfg.url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      fp);
    curl_easy_setopt(curl, CURLOPT_CAINFO,         cfg.ca_cert_path.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,      5L);
    // 10 s connect timeout, 300 s total transfer limit
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        300L);
    // Progress: allow cancel check via XFERINFOFUNCTION
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    CURLcode res = curl_easy_perform(curl);

    std::fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::remove(cfg.staging_path.c_str());
        setError(std::string("CURL error: ") + curl_easy_strerror(res));
        return false;
    }

    std::cout << "[FirmwareUpdate] Download complete: " << cfg.staging_path << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// verifySha256  –  compute SHA-256 of staging file and compare to expected
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::verifySha256(const FirmwareUpdateConfig& cfg)
{
    std::cout << "[FirmwareUpdate] Verifying SHA-256..." << std::endl;

    // Open the staged binary
    std::ifstream ifs(cfg.staging_path, std::ios::binary);
    if (!ifs.is_open()) {
        setError("Cannot open staging file for verification: " + cfg.staging_path);
        return false;
    }

    // Compute digest incrementally
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        setError("EVP_MD_CTX_new() failed");
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        setError("EVP_DigestInit_ex failed");
        return false;
    }

    const size_t BUF_SIZE = 65536;
    char buf[BUF_SIZE];
    while (ifs.read(buf, BUF_SIZE) || ifs.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buf, static_cast<size_t>(ifs.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            setError("EVP_DigestUpdate failed");
            return false;
        }
    }
    ifs.close();

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        setError("EVP_DigestFinal_ex failed");
        return false;
    }
    EVP_MD_CTX_free(ctx);

    // Convert to lowercase hex string
    std::ostringstream hex;
    hex << std::hex;
    for (unsigned int i = 0; i < digest_len; ++i) {
        hex.width(2);
        hex.fill('0');
        hex << static_cast<unsigned int>(digest[i]);
    }
    std::string computed = hex.str();

    // Case-insensitive comparison
    std::string expected = cfg.expected_sha256;
    for (char& c : expected) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

    if (computed != expected) {
        setError("SHA-256 mismatch! Expected: " + expected + "  Got: " + computed);
        std::remove(cfg.staging_path.c_str());
        return false;
    }

    std::cout << "[FirmwareUpdate] SHA-256 verified: " << computed << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// applyUpdate  –  backup current binary, then atomic rename of staging file
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::applyUpdate(const FirmwareUpdateConfig& cfg)
{
    std::cout << "[FirmwareUpdate] Applying update to " << cfg.target_path << std::endl;

    // Backup existing binary if it exists
    if (!cfg.backup_path.empty()) {
        struct stat st;
        if (stat(cfg.target_path.c_str(), &st) == 0) {
            if (std::rename(cfg.target_path.c_str(), cfg.backup_path.c_str()) != 0) {
                setError(std::string("Failed to backup current binary: ") +
                         strerror(errno));
                std::remove(cfg.staging_path.c_str());
                return false;
            }
            std::cout << "[FirmwareUpdate] Previous binary backed up to "
                      << cfg.backup_path << std::endl;
        }
    }

    // Set executable permissions on staging file
    if (chmod(cfg.staging_path.c_str(), 0755) != 0) {
        setError(std::string("chmod on staging file failed: ") + strerror(errno));
        std::remove(cfg.staging_path.c_str());
        return false;
    }

    // Atomic swap: rename staging → target
    if (std::rename(cfg.staging_path.c_str(), cfg.target_path.c_str()) != 0) {
        setError(std::string("rename() failed: ") + strerror(errno) +
                 ".  staging=" + cfg.staging_path +
                 "  target=" + cfg.target_path);
        // Attempt rollback of backup if rename failed
        if (!cfg.backup_path.empty())
            std::rename(cfg.backup_path.c_str(), cfg.target_path.c_str());
        return false;
    }

    std::cout << "[FirmwareUpdate] Binary installed at " << cfg.target_path << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// rollback  –  restore the backup binary over the target path
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::rollback()
{
    if (m_thread_running) {
        setError("Cannot rollback while an update is in progress");
        return false;
    }

    const std::string& backup = m_active_config.backup_path;
    const std::string& target = m_active_config.target_path;

    if (backup.empty() || target.empty()) {
        setError("No backup/target path configured for rollback");
        return false;
    }

    struct stat st;
    if (stat(backup.c_str(), &st) != 0) {
        setError("Backup binary not found at: " + backup);
        return false;
    }

    if (std::rename(backup.c_str(), target.c_str()) != 0) {
        setError(std::string("Rollback rename failed: ") + strerror(errno));
        return false;
    }

    std::cout << "[FirmwareUpdate] Rollback successful. Restored: " << target << std::endl;
    m_status.store(FirmwareUpdateStatus::IDLE);
    return true;
}

// ---------------------------------------------------------------------------
// waitForCompletion
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::waitForCompletion(unsigned int timeout_s)
{
    if (!m_thread_running) return true;

    if (timeout_s == 0) {
        pthread_join(m_thread, nullptr);
        return true;
    }

    // Poll until done or timeout
    for (unsigned int elapsed = 0; elapsed < timeout_s; ++elapsed) {
        if (!m_thread_running) return true;
        sleep(1);
    }
    return !m_thread_running;
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------
void FirmwareUpdateManager::cancel()
{
    FirmwareUpdateStatus cur = m_status.load();
    if (cur == FirmwareUpdateStatus::DOWNLOADING ||
        cur == FirmwareUpdateStatus::VERIFYING) {
        m_cancel_requested = true;
        std::cout << "[FirmwareUpdate] Cancel requested." << std::endl;
    }
}

// ---------------------------------------------------------------------------
// getLastError
// ---------------------------------------------------------------------------
std::string FirmwareUpdateManager::getLastError() const
{
    pthread_mutex_lock(const_cast<pthread_mutex_t*>(&m_mutex));
    std::string err = m_last_error;
    pthread_mutex_unlock(const_cast<pthread_mutex_t*>(&m_mutex));
    return err;
}

// ---------------------------------------------------------------------------
// setError  (internal)
// ---------------------------------------------------------------------------
void FirmwareUpdateManager::setError(const std::string& msg)
{
    pthread_mutex_lock(&m_mutex);
    m_last_error = msg;
    pthread_mutex_unlock(&m_mutex);
    std::cerr << "[FirmwareUpdate] ERROR: " << msg << std::endl;
}

// ---------------------------------------------------------------------------
// isHttpsUrl  –  reject plain HTTP downloads
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::isHttpsUrl(const std::string& url) const
{
    return url.size() >= 8 &&
           url.substr(0, 8) == "https://";
}

// ---------------------------------------------------------------------------
// compareSemver  –  returns 1 / 0 / -1 / -2(error)
// ---------------------------------------------------------------------------
int FirmwareUpdateManager::compareSemver(const std::string& a,
                                         const std::string& b)
{
    auto parse = [](const std::string& v, int& major, int& minor, int& patch) -> bool {
        // Accepts "MAJOR.MINOR.PATCH" with optional leading 'v'
        const char* s = v.c_str();
        if (*s == 'v' || *s == 'V') ++s;
        return std::sscanf(s, "%d.%d.%d", &major, &minor, &patch) == 3;
    };

    int amaj = 0, amin = 0, apat = 0;
    int bmaj = 0, bmin = 0, bpat = 0;

    if (!parse(a, amaj, amin, apat) || !parse(b, bmaj, bmin, bpat))
        return -2;

    if (amaj != bmaj) return amaj > bmaj ? 1 : -1;
    if (amin != bmin) return amin > bmin ? 1 : -1;
    if (apat != bpat) return apat > bpat ? 1 : -1;
    return 0;
}
