/**
 * otp_manager.cpp  –  RFC 6238 TOTP implementation
 *
 * Uses OpenSSL for:
 *   - RAND_bytes  (secret generation)
 *   - HMAC-SHA1   (HOTP MAC per RFC 4226)
 *   - CRYPTO_memcmp for constant-time comparison
 */

#include "otp_manager.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <iostream>

// ---------------------------------------------------------------------------
// Base-32 alphabet (RFC 4648)
// ---------------------------------------------------------------------------
static const char B32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ---------------------------------------------------------------------------
// OTPManager::generateSecret
// ---------------------------------------------------------------------------
std::string OTPManager::generateSecret()
{
    uint8_t raw[SECRET_BYTES];
    if (RAND_bytes(raw, SECRET_BYTES) != 1) {
        std::cerr << "[OTPManager] RAND_bytes failed\n";
        return "";
    }
    return base32Encode(raw, SECRET_BYTES);
}

// ---------------------------------------------------------------------------
// OTPManager::base32Encode
// ---------------------------------------------------------------------------
std::string OTPManager::base32Encode(const uint8_t* data, size_t len)
{
    std::string result;
    result.reserve((len * 8 + 4) / 5);

    int bits = 0, acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc   = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += B32_ALPHA[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0)
        result += B32_ALPHA[(acc << (5 - bits)) & 0x1F];

    return result;   // no '=' padding — authenticator apps tolerate this
}

// ---------------------------------------------------------------------------
// OTPManager::base32Decode
// ---------------------------------------------------------------------------
std::string OTPManager::base32Decode(const std::string& encoded)
{
    std::string result;
    int bits = 0, acc = 0;

    for (char c : encoded) {
        if (c == '=' || c == ' ' || c == '\n' || c == '\r')
            continue;  // skip padding and whitespace

        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        const char* p = std::strchr(B32_ALPHA, c);
        if (!p) {
            std::cerr << "[OTPManager] base32Decode: invalid char '" << c << "'\n";
            return "";
        }

        acc   = (acc << 5) | static_cast<int>(p - B32_ALPHA);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            result += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// OTPManager::hmacSHA1
// ---------------------------------------------------------------------------
std::string OTPManager::hmacSHA1(const std::string& key, const std::string& msg)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;

    HMAC(EVP_sha1(),
         key.data(),  static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
         digest, &digest_len);

    return std::string(reinterpret_cast<char*>(digest), digest_len);
}

// ---------------------------------------------------------------------------
// OTPManager::dynamicTruncate  (RFC 4226 §5.3)
// ---------------------------------------------------------------------------
uint32_t OTPManager::dynamicTruncate(const std::string& hmac20)
{
    if (hmac20.size() < 20) return 0;

    // offset = low nibble of last byte
    unsigned offset = static_cast<unsigned char>(hmac20[19]) & 0x0F;

    uint32_t code =
        (static_cast<uint32_t>(static_cast<unsigned char>(hmac20[offset    ])) << 24) |
        (static_cast<uint32_t>(static_cast<unsigned char>(hmac20[offset + 1])) << 16) |
        (static_cast<uint32_t>(static_cast<unsigned char>(hmac20[offset + 2])) <<  8) |
        (static_cast<uint32_t>(static_cast<unsigned char>(hmac20[offset + 3])));

    return code & 0x7FFFFFFF;   // mask sign bit
}

// ---------------------------------------------------------------------------
// OTPManager::generateTOTP
// ---------------------------------------------------------------------------
std::string OTPManager::generateTOTP(const std::string& base32_secret,
                                     std::time_t now)
{
    if (now == 0) now = std::time(nullptr);

    std::string key = base32Decode(base32_secret);
    if (key.empty()) {
        std::cerr << "[OTPManager] generateTOTP: failed to decode secret\n";
        return "";
    }

    // T = floor(Unix-time / step)
    uint64_t T = static_cast<uint64_t>(now) / static_cast<uint64_t>(OTP_STEP);

    // Encode T as big-endian 8-byte counter
    uint8_t counter[8];
    for (int i = 7; i >= 0; --i) {
        counter[i] = static_cast<uint8_t>(T & 0xFF);
        T >>= 8;
    }
    std::string msg(reinterpret_cast<char*>(counter), 8);

    std::string hmac = hmacSHA1(key, msg);
    uint32_t code = dynamicTruncate(hmac) % 1000000;   // 6 digits

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(OTP_DIGITS) << code;
    return oss.str();
}

// ---------------------------------------------------------------------------
// OTPManager::verifyTOTP
// ---------------------------------------------------------------------------
bool OTPManager::verifyTOTP(const std::string& base32_secret,
                            const std::string& otp,
                            std::time_t now)
{
    // Structural pre-checks (fail fast)
    if (static_cast<int>(otp.size()) != OTP_DIGITS) return false;
    for (char c : otp)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;

    if (now == 0) now = std::time(nullptr);

    // Check the current window plus ±OTP_WINDOW adjacent steps for clock skew
    for (int step = -OTP_WINDOW; step <= OTP_WINDOW; ++step) {
        std::time_t t = now + static_cast<std::time_t>(step * OTP_STEP);
        std::string expected = generateTOTP(base32_secret, t);
        if (expected.empty()) continue;

        // Constant-time comparison to prevent timing oracle
        if (expected.size() == otp.size() &&
            CRYPTO_memcmp(expected.data(), otp.data(), expected.size()) == 0)
        {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// OTPManager::buildOtpauthURI
// ---------------------------------------------------------------------------
std::string OTPManager::buildOtpauthURI(const std::string& issuer,
                                        const std::string& account,
                                        const std::string& base32_secret)
{
    // Minimal percent-encode for the label components
    // (only encode characters outside unreserved set that would break the URI)
    auto pctEncode = [](const std::string& s) -> std::string {
        std::string out;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                out += c;
            } else {
                char buf[4];
                std::snprintf(buf, sizeof(buf), "%%%02X", c);
                out += buf;
            }
        }
        return out;
    };

    std::string label = pctEncode(issuer) + ":" + pctEncode(account);
    return "otpauth://totp/" + label +
           "?secret=" + base32_secret +
           "&issuer=" + pctEncode(issuer) +
           "&algorithm=SHA1&digits=6&period=30";
}
