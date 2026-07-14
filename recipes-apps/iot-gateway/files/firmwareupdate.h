#ifndef FIRMWAREUPDATE_H
#define FIRMWAREUPDATE_H

/**
 * firmwareupdate.h  –  OTA Firmware Update Manager for IoT Gateway
 *
 * Provides secure over-the-air firmware update functionality:
 *   - Authenticated download via HTTPS (mutual TLS or bearer token)
 *   - SHA-256 checksum verification before applying
 *   - Atomic swap: writes to a staging path, then renames into place
 *   - Rollback support: keeps the previous binary for one-step recovery
 *   - Version comparison: skips download if current version is up-to-date
 *   - Non-blocking: runs in its own pthread and signals completion via
 *     an std::atomic<FirmwareUpdateStatus> that callers can poll
 *
 * ─── SECURITY NOTES ─────────────────────────────────────────────────────────
 *  - The update URL must use HTTPS; plain HTTP is rejected.
 *  - A CA certificate is required for server verification (no skip-verify).
 *  - The expected SHA-256 digest (hex, 64 chars) must be provided before the
 *    download is triggered; the binary is never applied without a match.
 *  - The staging file is written to a tmpfs or the same filesystem as the
 *    target to guarantee an atomic rename(2) swap.
 *  - Downloaded binaries are installed with chmod 0755 (executable, not
 *    world-writable) and owned by root.
 *
 * ─── DEPENDENCIES ───────────────────────────────────────────────────────────
 *  libcurl   – HTTPS download with TLS peer verification
 *  openssl   – SHA-256 digest computation (EVP_DigestUpdate)
 *  pthread   – background update thread
 */

#include <string>
#include <atomic>
#include <pthread.h>
#include <cstdint>

// ---------------------------------------------------------------------------
// FirmwareUpdateStatus – lifecycle states for the background update thread
// ---------------------------------------------------------------------------
enum class FirmwareUpdateStatus : uint8_t {
    IDLE        = 0,   // no update in progress
    DOWNLOADING = 1,   // fetching firmware binary from remote URL
    VERIFYING   = 2,   // computing and comparing SHA-256 checksum
    APPLYING    = 3,   // writing staging file and performing atomic swap
    SUCCESS     = 4,   // update complete; reboot required
    FAILED      = 5    // update aborted; previous binary untouched
};

// Human-readable label for logging / dashboard display
const char* firmwareStatusLabel(FirmwareUpdateStatus s);

// ---------------------------------------------------------------------------
// FirmwareUpdateConfig – parameters for a single update operation
// ---------------------------------------------------------------------------
struct FirmwareUpdateConfig {
    std::string url;             // HTTPS URL of the firmware binary
    std::string expected_sha256; // expected SHA-256 hex digest (64 chars)
    std::string ca_cert_path;    // PEM CA certificate for TLS verification
    std::string staging_path;    // temporary download path (same FS as target)
    std::string target_path;     // final installation path, e.g. /usr/bin/iot-gateway
    std::string backup_path;     // path for the previous binary (rollback)
    std::string version;         // version string of the new firmware (e.g. "1.2.3")
};

// ---------------------------------------------------------------------------
// FirmwareHeader – binary header at byte offset 0 of every .ldr firmware image
//
// File layout:  [ FirmwareHeader (116 bytes) ][ payload (payload_size bytes) ]
//
// hdr_crc32  covers bytes 0–111 (all header fields except hdr_crc32 itself).
// sha256     is the raw 32-byte SHA-256 digest of the payload region only.
// ---------------------------------------------------------------------------

static constexpr uint8_t  LDR_MAGIC[4]    = {'R', 'P', 'I', 'F'};
static constexpr uint16_t LDR_HDR_VERSION = 1;
static constexpr uint16_t LDR_HDR_SIZE    = 116;  // sizeof(FirmwareHeader)

typedef struct __attribute__((packed)) {
    uint8_t  magic[4];        /* "RPIF"                              */
    uint16_t hdr_version;     /* must be 1                           */
    uint16_t hdr_size;        /* must be 116                         */
    char     fw_version[32];  /* e.g. "v0.1.0\0..."                  */
    char     timestamp[32];   /* e.g. "2026-06-29T16:36:52Z\0..."    */
    uint8_t  sha256[32];      /* raw SHA-256 digest of payload       */
    uint64_t payload_size;    /* byte count of the payload region    */
    uint32_t hdr_crc32;       /* CRC32/ISO-HDLC of header[0..111]   */
} FirmwareHeader;

// ---------------------------------------------------------------------------
// FirmwareUpdateManager
// ---------------------------------------------------------------------------
class FirmwareUpdateManager {
public:
    /**
     * Construct with the path of the currently running binary and its version.
     *
     * @param current_binary_path  Absolute path to the running executable.
     * @param current_version      Semver string of the running firmware.
     */
    FirmwareUpdateManager(const std::string& current_binary_path,
                          const std::string& current_version);

    ~FirmwareUpdateManager();

    // Prevent copying (owns pthread_t and mutex state)
    FirmwareUpdateManager(const FirmwareUpdateManager&) = delete;
    FirmwareUpdateManager& operator=(const FirmwareUpdateManager&) = delete;

    // -----------------------------------------------------------------------
    // Trigger an OTA update in a background thread.
    //
    // Returns true if the thread was started successfully.
    // Returns false if an update is already in progress or config is invalid.
    // -----------------------------------------------------------------------
    bool startUpdate(const FirmwareUpdateConfig& config);

    // -----------------------------------------------------------------------
    // Attempt to roll back to the backup binary created during the last
    // successful update.  Must be called while no update thread is running.
    // Returns true on success.
    // -----------------------------------------------------------------------
    bool rollback();

    // -----------------------------------------------------------------------
    // Block until the background update thread finishes (or until timeout_s
    // seconds elapse).  Pass 0 to wait indefinitely.
    // Returns true if the thread finished within the timeout.
    // -----------------------------------------------------------------------
    bool waitForCompletion(unsigned int timeout_s = 0);

    // -----------------------------------------------------------------------
    // Cancel an in-progress download.  The staging file is removed.
    // Has no effect if status is APPLYING, SUCCESS, or FAILED.
    // -----------------------------------------------------------------------
    void cancel();

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    FirmwareUpdateStatus getStatus() const { return m_status.load(); }
    std::string          getLastError() const;
    std::string          getCurrentVersion() const { return m_current_version; }

    // -----------------------------------------------------------------------
    // Compare two semver strings (MAJOR.MINOR.PATCH).
    // Returns  1 if a > b,  0 if a == b,  -1 if a < b.
    // Returns -2 on parse error.
    // -----------------------------------------------------------------------
    static int compareSemver(const std::string& a, const std::string& b);

    // -----------------------------------------------------------------------
    // Verify the 116-byte header of a .ldr firmware image.
    //
    // Checks performed:
    //   1. magic bytes == "RPIF"
    //   2. hdr_version == 1
    //   3. hdr_size    == 116
    //   4. CRC32/ISO-HDLC of header[0..111] matches hdr_crc32
    //   5. fw_version and timestamp fields are null-terminated
    //   6. payload_size is consistent with the actual file size
    //
    // Returns true and populates header_out on success.
    // Returns false and populates error_out with a human-readable reason.
    // -----------------------------------------------------------------------
    static bool verifyLdrHeader(const std::string& ldr_path,
                                FirmwareHeader&    header_out,
                                std::string&       error_out);

private:
    // Background thread entry point
    static void* updateThreadEntry(void* arg);

    // Ordered update steps – each returns false on failure and sets m_error
    bool downloadFirmware(const FirmwareUpdateConfig& cfg);
    bool verifySha256(const FirmwareUpdateConfig& cfg);
    bool applyUpdate(const FirmwareUpdateConfig& cfg);

    // CURL write callback
    static size_t curlWriteCallback(void* ptr, size_t size,
                                    size_t nmemb, void* userdata);

    // Internal helpers
    void setError(const std::string& msg);
    bool isHttpsUrl(const std::string& url) const;
    static bool isLdrFile(const std::string& path);

    // -----------------------------------------------------------------------
    // Member state
    // -----------------------------------------------------------------------
    std::string               m_current_binary_path;
    std::string               m_current_version;

    pthread_t                 m_thread;
    pthread_mutex_t           m_mutex;
    bool                      m_thread_running;

    std::atomic<bool>         m_cancel_requested;
    std::atomic<FirmwareUpdateStatus> m_status;

    // Guarded by m_mutex
    std::string               m_last_error;

    // A copy of the config used by the background thread
    FirmwareUpdateConfig      m_active_config;

    // .ldr image state – populated during verifyLdrHeader
    FirmwareHeader            m_ldr_header;     // parsed header of current .ldr update
    bool                      m_is_ldr_update;  // true when staged firmware is .ldr format
};

#endif // FIRMWAREUPDATE_H
