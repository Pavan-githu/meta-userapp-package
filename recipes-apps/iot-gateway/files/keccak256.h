#ifndef KECCAK256_H
#define KECCAK256_H

/**
 * keccak256.h  –  Ethereum-compatible Keccak-256 digest
 *
 * IMPORTANT: This is NOT SHA3-256. Ethereum uses the original Keccak proposal
 * with 0x01 domain-separation padding, whereas NIST SHA3 uses 0x06. The two
 * produce different digests for the same input.
 *
 * Usage:
 *   uint8_t digest[32];
 *   keccak256_raw((uint8_t*)"hello", 5, digest);  // raw 32-byte output
 *
 *   std::string hex = keccak256_hex("hello");      // 64-char lowercase hex
 *   std::string h   = keccak256_0x("hello");       // "0x" + 64-char hex
 */

#include <cstddef>
#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// C interface (also callable from C)
// ---------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute keccak256(in, in_len) and write 32 bytes into out[].
 */
void keccak256_raw(const uint8_t* in, size_t in_len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

// ---------------------------------------------------------------------------
// C++ helpers
// ---------------------------------------------------------------------------
#ifdef __cplusplus

/** Returns keccak256(data) as a 64-char lowercase hex string (no "0x"). */
std::string keccak256_hex(const std::string& data);

/** Returns keccak256(data) as "0x" + 64-char lowercase hex string. */
std::string keccak256_0x(const std::string& data);

#endif // __cplusplus

#endif // KECCAK256_H
