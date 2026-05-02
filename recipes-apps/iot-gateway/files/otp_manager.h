#ifndef OTP_MANAGER_H
#define OTP_MANAGER_H

/**
 * otp_manager.h  –  RFC 6238 TOTP (Time-based One-Time Password)
 *
 * Implements TOTP using HMAC-SHA1 as the underlying MAC (RFC 4226 HOTP base
 * with a time-derived counter per RFC 6238).
 *
 * Shared secrets are stored per-user in the UserAuth registry as base32-
 * encoded strings compatible with Google Authenticator / Authy / FreeOTP.
 *
 * Key design choices:
 *   - 6-digit codes   (OTP_DIGITS = 6)
 *   - 30-second step  (OTP_STEP   = 30)
 *   - ±1 window       (OTP_WINDOW = 1)  – tolerates up to 30 s clock drift
 *   - 160-bit (20-byte) secret via OpenSSL RAND_bytes
 *
 * Blockchain linkage points:
 *   1. The TOTP secret is generated once at registration and stored in the
 *      device's UserAuth registry (never transmitted on-chain; only the
 *      result of OTP verification is logged).
 *   2. Every OTP attempt (success or failure) emits an on-chain transaction
 *      via BlockchainLogger, giving an immutable, tamper-proof audit trail.
 *   3. Account lockout state is stored on-chain: 3 OTP failures → locked;
 *      unlock requires an admin transaction on the IoTAuthLog contract.
 */

#include <string>
#include <ctime>
#include <cstdint>

class OTPManager {
public:
    static const int OTP_DIGITS   = 6;    // code length
    static const int OTP_STEP     = 30;   // seconds per time-step (RFC 6238)
    static const int OTP_WINDOW   = 1;    // accept ±1 adjacent steps
    static const int SECRET_BYTES = 20;   // 160-bit shared secret

    // -----------------------------------------------------------------------
    // Secret management
    // -----------------------------------------------------------------------

    /**
     * Generate a new random 160-bit TOTP secret and return it base32-encoded
     * (32 uppercase chars, no padding). Returns empty string on crypto failure.
     */
    static std::string generateSecret();

    // -----------------------------------------------------------------------
    // Code generation / verification
    // -----------------------------------------------------------------------

    /**
     * Compute the current TOTP code for the given base32 secret.
     * If now == 0 the current wall-clock time is used.
     * Returns a zero-padded 6-digit string (e.g. "042718"), or "" on error.
     */
    static std::string generateTOTP(const std::string& base32_secret,
                                    std::time_t now = 0);

    /**
     * Verify user-supplied otp against base32_secret within ±OTP_WINDOW steps.
     * Uses constant-time string comparison to resist timing side-channels.
     * If now == 0 the current wall-clock time is used.
     */
    static bool verifyTOTP(const std::string& base32_secret,
                           const std::string& otp,
                           std::time_t now = 0);

    // -----------------------------------------------------------------------
    // Authenticator-app setup
    // -----------------------------------------------------------------------

    /**
     * Build the otpauth:// URI understood by Google Authenticator, Authy, etc.
     * Display this as a QR code during user registration so the user can
     * add the device to their authenticator app.
     *
     *   issuer:   e.g. "RaceIoT-Gateway"
     *   account:  the username
     *   secret:   base32-encoded secret from generateSecret()
     *
     * Returns: "otpauth://totp/<issuer>:<account>?secret=<SECRET>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30"
     */
    static std::string buildOtpauthURI(const std::string& issuer,
                                       const std::string& account,
                                       const std::string& base32_secret);

private:
    // base32 encode raw bytes (RFC 4648, uppercase, no padding)
    static std::string base32Encode(const uint8_t* data, size_t len);

    // base32 decode to raw bytes; returns "" on invalid input
    static std::string base32Decode(const std::string& encoded);

    // HMAC-SHA1(key, msg) → 20-byte string using OpenSSL
    static std::string hmacSHA1(const std::string& key,
                                const std::string& msg);

    // RFC 4226 §5.3 dynamic truncation
    static uint32_t dynamicTruncate(const std::string& hmac20);
};

#endif // OTP_MANAGER_H
