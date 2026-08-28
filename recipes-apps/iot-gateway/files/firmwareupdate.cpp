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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <vector>

// ---------------------------------------------------------------------------
// crc32Compute  –  CRC-32/ISO-HDLC (poly 0xEDB88320, init 0xFFFFFFFF,
//                  final XOR 0xFFFFFFFF).  Compatible with zlib crc32(),
//                  zip, and Ethernet FCS.
//
// The lookup table is built on first call; C++11 guarantees the static
// local is initialised exactly once even in a multithreaded environment.
// ---------------------------------------------------------------------------
static uint32_t crc32Compute(const uint8_t* data, size_t len)
{
    struct Table {
        uint32_t t[256];
        Table() {
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t c = i;
                for (int k = 0; k < 8; ++k)
                    c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                t[i] = c;
            }
        }
    };
    static const Table tbl;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = tbl.t[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

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
// verifyLdrHeader  –  validate the 48-byte header of a .ldr firmware image
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::verifyLdrHeader(const std::string& ldr_path,
                                             FirmwareHeader&    header_out,
                                             std::string&       error_out)
{
    // Open file and determine size
    std::ifstream ifs(ldr_path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        error_out = "Cannot open firmware file: " + ldr_path;
        return false;
    }
    const std::streamoff file_size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    // File must be at least as large as the header
    if (file_size < static_cast<std::streamoff>(LDR_HDR_SIZE)) {
        error_out = "File too small to contain a valid .ldr header ("
                    + std::to_string(static_cast<long long>(file_size)) + " bytes)";
        return false;
    }

    // Read header bytes
    FirmwareHeader hdr;
    if (!ifs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr))) {
        error_out = "Failed to read firmware header from: " + ldr_path;
        return false;
    }
    ifs.close();

    // ── 1. Magic bytes ────────────────────────────────────────────────────
    if (std::memcmp(hdr.magic, LDR_MAGIC, sizeof(LDR_MAGIC)) != 0) {
        error_out = std::string("Invalid magic bytes: expected 'RPIF', got '")
                    + static_cast<char>(hdr.magic[0])
                    + static_cast<char>(hdr.magic[1])
                    + static_cast<char>(hdr.magic[2])
                    + static_cast<char>(hdr.magic[3]) + "'";
        return false;
    }
    // ── 2. CRC32 of header bytes 0..43 ───────────────────────────────────
    //  hdr_crc32 sits at offset 44 (LDR_HDR_SIZE - sizeof(uint32_t));
    //  it is NOT included in the digest.
    const size_t   covered_len = LDR_HDR_SIZE - sizeof(uint32_t); // 44
    const uint32_t computed    = crc32Compute(
                                     reinterpret_cast<const uint8_t*>(&hdr),
                                     covered_len);
    if (computed != hdr.hdr_crc32) {
        std::ostringstream oss;
        oss << std::hex << std::uppercase
            << "Header CRC32 mismatch: computed 0x" << computed
            << ", stored 0x" << hdr.hdr_crc32;
        error_out = oss.str();
        return false;
    }

    header_out = hdr;
    std::cout << "[FirmwareUpdate] .ldr header valid: payload=" << hdr.payload_size << " bytes" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// isLdrFile  –  true when path ends with ".ldr" (case-sensitive)
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::isLdrFile(const std::string& path)
{
    return path.size() > 4 &&
           path.compare(path.size() - 4, 4, ".ldr") == 0;
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
    , m_is_ldr_update(false)
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
    FirmwareUpdateConfig cfg = self->m_active_config;
    self->m_is_ldr_update = false;
    std::string ldr_original_path;  // original .ldr path, kept alive until after HSM verify

    auto fail = [&](const std::string& msg) {
        self->setError(msg);
        self->m_status.store(FirmwareUpdateStatus::FAILED);
        if (!cfg.staging_path.empty())
            std::remove(cfg.staging_path.c_str());
        if (!ldr_original_path.empty())
            std::remove(ldr_original_path.c_str());
        self->m_thread_running = false;
        pthread_exit(nullptr);
    };

    // Step 1: Download
    // Carry the .ldr extension from the URL to the staging file so that
    // isLdrFile() works on the staged path without relying on magic-byte probing.
    if (isLdrFile(cfg.url) && !isLdrFile(cfg.staging_path))
        cfg.staging_path += ".ldr";

    if (!self->downloadFirmware(cfg))
        fail(self->getLastError());

    // Verify downloaded .ldr file size matches blockchain metadata
    if (cfg.bc_ldr_size_bytes > 0) {
        struct stat ldr_st;
        if (::stat(cfg.staging_path.c_str(), &ldr_st) == 0 &&
            static_cast<uint64_t>(ldr_st.st_size) != cfg.bc_ldr_size_bytes) {
            fail("Downloaded .ldr size mismatch: blockchain=" +
                 std::to_string(cfg.bc_ldr_size_bytes) +
                 " actual=" + std::to_string(ldr_st.st_size));
        }
    }

    if (self->m_cancel_requested.load()) {
        fail("Update cancelled by caller");
    }

    if (self->isLdrFile(cfg.staging_path)) {
        FirmwareHeader hdr;
        std::string    hdr_err;
        if (!FirmwareUpdateManager::verifyLdrHeader(cfg.staging_path, hdr, hdr_err))
            fail(std::string("LDR header validation failed: ") + hdr_err);
        self->m_ldr_header    = hdr;
        self->m_is_ldr_update = true;

        // Verify extracted payload size matches blockchain metadata
        if (cfg.bc_payload_size_bytes > 0 &&
            hdr.payload_size != cfg.bc_payload_size_bytes) {
            fail("Payload size mismatch: blockchain=" +
                 std::to_string(cfg.bc_payload_size_bytes) +
                 " header=" + std::to_string(hdr.payload_size));
        }

        // Convert hdr.sha256 to hex and verify it matches the blockchain metadata hash.
        // This ensures the RPIF header was not tampered with after the blockchain record was made.
        std::ostringstream hdr_hex;
        hdr_hex << std::hex;
        for (int i = 0; i < 32; ++i) {
            hdr_hex.width(2); hdr_hex.fill('0');
            hdr_hex << static_cast<unsigned int>(hdr.sha256[i]);
        }
        std::string hdr_hash = hdr_hex.str();
        std::string bc_hash  = cfg.expected_sha256;
        for (char& c : bc_hash) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (hdr_hash != bc_hash)
            fail("RPIF header sha256 does not match blockchain metadata hash:\n"
                 "  header   : " + hdr_hash + "\n"
                 "  blockchain: " + bc_hash);

        // Update paths before extraction so fail() can clean up both files
        ldr_original_path = cfg.staging_path;
        cfg.staging_path  = ldr_original_path + ".raucb";

        // Extract exactly payload_size bytes starting at LDR_HDR_SIZE
        {
            std::ifstream src(ldr_original_path, std::ios::binary);
            std::ofstream dst(cfg.staging_path,   std::ios::binary | std::ios::trunc);
            if (!src || !dst)
                fail("Cannot extract .ldr payload to: " + cfg.staging_path);
            src.seekg(LDR_HDR_SIZE, std::ios::beg);
            uint64_t remaining = hdr.payload_size;
            char copy_buf[65536];
            while (remaining > 0) {
                size_t chunk = static_cast<size_t>(
                    std::min(static_cast<uint64_t>(sizeof(copy_buf)), remaining));
                src.read(copy_buf, static_cast<std::streamsize>(chunk));
                size_t n = static_cast<size_t>(src.gcount());
                if (n == 0) break;
                dst.write(copy_buf, static_cast<std::streamsize>(n));
                remaining -= n;
            }
        }
        std::cout << "[FirmwareUpdate] .ldr payload extracted ("
                  << hdr.payload_size << " bytes) \u2192 " << cfg.staging_path << std::endl;
    }

    // Step 1.5: Verify Google Cloud HSM signature from the RPIS tail of the original
    //           .ldr file.  The signature covers the same payload bytes now in
    //           cfg.staging_path, so we pass ldr_original_path for the tail read.
    if (self->m_is_ldr_update && !cfg.hsm_pubkey_path.empty()) {
        std::string hsm_err;
        bool hsm_ok = FirmwareUpdateManager::verifyHsmSignatureFromLdr(
            ldr_original_path, cfg.hsm_pubkey_path,
            self->m_ldr_header.payload_size, hsm_err);
        if (!hsm_ok)
            fail(hsm_err);
    }
    // Original .ldr is no longer needed; payload lives in cfg.staging_path
    if (!ldr_original_path.empty()) {
        std::remove(ldr_original_path.c_str());
        ldr_original_path.clear();
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
// verifyHsmSignature  –  EVP_DigestVerify over the firmware file using the
//                        Google Cloud HSM RSA-PSS or ECDSA-P256 public key.
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::verifyHsmSignature(const std::string& firmware_path,
                                                const std::string& sig_path,
                                                const std::string& pubkey_path,
                                                std::string&       error_out)
{
    // Load HSM public key from PEM (exported from Google Cloud KMS)
    FILE* kfp = fopen(pubkey_path.c_str(), "r");
    if (!kfp) { error_out = "Cannot open HSM public key: " + pubkey_path; return false; }
    EVP_PKEY* pkey = PEM_read_PUBKEY(kfp, nullptr, nullptr, nullptr);
    fclose(kfp);
    if (!pkey) {
        error_out = "Failed to parse HSM public key from: " + pubkey_path;
        return false;
    }

    // Read detached signature file (binary, max 1 KiB – RSA-4096 = 512 bytes)
    FILE* sfp = fopen(sig_path.c_str(), "rb");
    if (!sfp) {
        EVP_PKEY_free(pkey);
        error_out = "Cannot open signature file: " + sig_path;
        return false;
    }
    fseek(sfp, 0, SEEK_END);
    long sig_len = ftell(sfp);
    fseek(sfp, 0, SEEK_SET);
    if (sig_len <= 0 || sig_len > 4096) {
        fclose(sfp);
        EVP_PKEY_free(pkey);
        error_out = "Signature file has unexpected size: " + std::to_string(sig_len);
        return false;
    }
    std::vector<uint8_t> sig(static_cast<size_t>(sig_len));
    fread(sig.data(), 1, static_cast<size_t>(sig_len), sfp);
    fclose(sfp);

    // Stream firmware file through EVP_DigestVerify (SHA-256, RSA-PSS or ECDSA)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); error_out = "EVP_MD_CTX_new() failed"; return false; }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        error_out = "EVP_DigestVerifyInit failed";
        return false;
    }

    FILE* ffp = fopen(firmware_path.c_str(), "rb");
    if (!ffp) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        error_out = "Cannot open firmware for HSM verification: " + firmware_path;
        return false;
    }
    uint8_t buf[65536];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), ffp)) > 0)
        EVP_DigestVerifyUpdate(ctx, buf, n);
    fclose(ffp);

    int ok = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (ok != 1) {
        error_out = "HSM signature INVALID — firmware rejected as inauthentic";
        return false;
    }
    std::cout << "[FirmwareUpdate] HSM signature verified OK (Google Cloud HSM)" << std::endl;
    return true;
}

// ---------------------------------------------------------------------------
// downloadUrlToFile  –  minimal CURL download for small companion files (.sig)
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::downloadUrlToFile(const std::string& url,
                                               const std::string& dest_path,
                                               const std::string& ca_cert_path,
                                               std::string&       error_out)
{
    FILE* fp = std::fopen(dest_path.c_str(), "wb");
    if (!fp) {
        error_out = "Cannot create: " + dest_path + " (" + strerror(errno) + ")";
        return false;
    }
    CURL* curl = curl_easy_init();
    if (!curl) { std::fclose(fp); error_out = "curl_easy_init() failed"; return false; }

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      fp);
    curl_easy_setopt(curl, CURLOPT_CAINFO,         ca_cert_path.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,      5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        30L);  // .sig files are small

    CURLcode res = curl_easy_perform(curl);
    std::fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::remove(dest_path.c_str());
        error_out = std::string("CURL error: ") + curl_easy_strerror(res);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// verifyHsmSignatureFromLdr  –  extract the RSA/ECDSA signature from the
//   264-byte RPIS tail appended to the .ldr file and verify it against the
//   .raucb payload (bytes LDR_HDR_SIZE .. LDR_HDR_SIZE+payload_size-1).
//
//   RPIS tail layout (264 bytes, little-endian):
//     [0:4]   magic "RPIS"
//     [4:6]   uint16_t: signature length in bytes
//     [6:8]   uint16_t: reserved (0)
//     [8:264] signature bytes (padded to 256 bytes)
// ---------------------------------------------------------------------------
bool FirmwareUpdateManager::verifyHsmSignatureFromLdr(const std::string& ldr_path,
                                                       const std::string& pubkey_path,
                                                       uint64_t           payload_size,
                                                       std::string&       error_out)
{
    // ── Read the RPIS tail from the end of the file ───────────────────────
    std::ifstream ldr(ldr_path, std::ios::binary | std::ios::ate);
    if (!ldr.is_open()) {
        error_out = "Cannot open .ldr for RPIS tail read: " + ldr_path;
        return false;
    }
    const std::streamoff file_size = ldr.tellg();
    if (file_size < static_cast<std::streamoff>(LDR_HDR_SIZE + payload_size + RPIS_TAIL_SIZE)) {
        error_out = "File too small to contain RPIS tail: " + ldr_path;
        return false;
    }

    // Seek to start of RPIS tail
    ldr.seekg(-static_cast<std::streamoff>(RPIS_TAIL_SIZE), std::ios::end);
    uint8_t tail[RPIS_TAIL_SIZE];
    if (!ldr.read(reinterpret_cast<char*>(tail), RPIS_TAIL_SIZE)) {
        error_out = "Failed to read RPIS tail from: " + ldr_path;
        return false;
    }
    ldr.close();

    // ── Validate magic ────────────────────────────────────────────────────
    if (std::memcmp(tail, RPIS_MAGIC, sizeof(RPIS_MAGIC)) != 0) {
        error_out = std::string("RPIS magic mismatch — expected 'RPIS', got '")
                    + static_cast<char>(tail[0]) + static_cast<char>(tail[1])
                    + static_cast<char>(tail[2]) + static_cast<char>(tail[3]) + "'";
        return false;
    }

    // ── Extract signature length and bytes ───────────────────────────────
    uint16_t sig_len = 0;
    std::memcpy(&sig_len, tail + 4, sizeof(sig_len));  // little-endian
    if (sig_len == 0 || sig_len > RPIS_SIG_MAX) {
        error_out = "RPIS sig_len invalid: " + std::to_string(sig_len);
        return false;
    }
    const uint8_t* sig_bytes = tail + RPIS_SIG_OFFSET;

    // ── Load HSM public key ──────────────────────────────────────────────
    FILE* kfp = fopen(pubkey_path.c_str(), "r");
    if (!kfp) { error_out = "Cannot open HSM public key: " + pubkey_path; return false; }
    EVP_PKEY* pkey = PEM_read_PUBKEY(kfp, nullptr, nullptr, nullptr);
    fclose(kfp);
    if (!pkey) { error_out = "Failed to parse HSM public key: " + pubkey_path; return false; }

    // ── Verify signature over the payload region only ────────────────────
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); error_out = "EVP_MD_CTX_new() failed"; return false; }

    EVP_PKEY_CTX* pkctx = nullptr;
    if (EVP_DigestVerifyInit(ctx, &pkctx, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        error_out = "EVP_DigestVerifyInit failed"; return false;
    }
    // Match Google Cloud KMS RSA_SIGN_PSS_2048_SHA256: PSS padding, salt = digest length
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        error_out = "Failed to set RSA-PSS padding parameters"; return false;
    }

    // Stream exactly payload_size bytes starting at LDR_HDR_SIZE
    std::ifstream pfs(ldr_path, std::ios::binary);
    if (!pfs.is_open()) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
        error_out = "Cannot open .ldr for payload verification: " + ldr_path;
        return false;
    }
    pfs.seekg(LDR_HDR_SIZE, std::ios::beg);
    uint64_t remaining = payload_size;
    uint8_t  pbuf[65536];
    while (remaining > 0) {
        size_t chunk = static_cast<size_t>(std::min((uint64_t)sizeof(pbuf), remaining));
        pfs.read(reinterpret_cast<char*>(pbuf), chunk);
        size_t n = static_cast<size_t>(pfs.gcount());
        if (n == 0) break;
        EVP_DigestVerifyUpdate(ctx, pbuf, n);
        remaining -= n;
    }
    pfs.close();

    int ok = EVP_DigestVerifyFinal(ctx,
                                    sig_bytes,
                                    static_cast<size_t>(sig_len));
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (ok != 1) {
        error_out = "RPIS HSM signature INVALID — .ldr payload not authentic";
        return false;
    }
    std::cout << "[FirmwareUpdate] RPIS HSM signature verified OK (Google Cloud HSM)" << std::endl;
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

    // staging_path is always the bare payload at this point (header/tail already stripped)
    uint64_t bytes_remaining = UINT64_MAX;  // read to EOF

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
    while (bytes_remaining > 0 && (ifs.read(buf, std::min((size_t)BUF_SIZE, (size_t)bytes_remaining)) || ifs.gcount() > 0)) {
        size_t n = static_cast<size_t>(ifs.gcount());
        if (n == 0) break;
        bytes_remaining -= (bytes_remaining == UINT64_MAX ? 0 : n);
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
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

    // Payload was extracted from the .ldr in updateThreadEntry; cfg.staging_path is
    // already the bare .raucb bundle — hand it directly to the RAUC daemon.
    if (m_is_ldr_update) {
        std::string cmd = "rauc install " + cfg.staging_path;
        std::cout << "[FirmwareUpdate] Running: " << cmd << std::endl;
        int ret = std::system(cmd.c_str());
        std::remove(cfg.staging_path.c_str());
        if (ret != 0) {
            setError("rauc install failed (exit " + std::to_string(ret) +
                     ") — inactive slot not written");
            return false;
        }
        std::cout << "[FirmwareUpdate] rauc install succeeded. "
                     "Device will boot new slot on next reboot." << std::endl;
        return true;
    }

    // ── Plain binary path (non-LDR) ───────────────────────────────────────
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
