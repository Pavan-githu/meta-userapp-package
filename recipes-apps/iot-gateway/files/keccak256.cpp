/**
 * keccak256.cpp  –  Ethereum-compatible Keccak-256 digest
 *
 * Implements the Keccak-f[1600] permutation with 136-byte rate and 0x01
 * domain-separation padding (Ethereum convention, NOT SHA3's 0x06).
 *
 * Algorithm constants taken from the public Keccak reference specification
 * (Bertoni, Daemen, Peeters, Van Assche) – these values are in the public
 * domain.
 */

#include "keccak256.h"

#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>

// ---------------------------------------------------------------------------
// Internal: Keccak-f[1600] permutation constants
// ---------------------------------------------------------------------------

// 24 round constants (LFSR-generated, from the Keccak spec)
static const uint64_t KF_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for the rho step (24 non-zero entries, one per lane index)
static const int KF_ROTC[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44
};

// Linear index permutation for the pi step (PILN table from the Keccak spec)
static const int KF_PILN[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,
     8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// ---------------------------------------------------------------------------
// Keccak-f[1600] round function applied 24 times
// ---------------------------------------------------------------------------
static void keccakf(uint64_t st[25])
{
    uint64_t bc[5], t;

    for (int round = 0; round < 24; ++round) {

        // ---- Theta ----
        for (int i = 0; i < 5; ++i)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];

        for (int i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // ---- Rho + Pi (combined) ----
        t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j  = KF_PILN[i];
            bc[0]  = st[j];
            st[j]  = ROTL64(t, KF_ROTC[i]);
            t      = bc[0];
        }

        // ---- Chi ----
        for (int j = 0; j < 25; j += 5) {
            uint64_t tmp[5];
            for (int i = 0; i < 5; ++i) tmp[i] = st[j + i];
            for (int i = 0; i < 5; ++i)
                st[j + i] ^= (~tmp[(i + 1) % 5]) & tmp[(i + 2) % 5];
        }

        // ---- Iota ----
        st[0] ^= KF_RC[round];
    }
}

// ---------------------------------------------------------------------------
// Public: keccak256_raw
// ---------------------------------------------------------------------------
void keccak256_raw(const uint8_t* in, size_t in_len, uint8_t out[32])
{
    static const size_t RATE  = 136;   // (1600 - 256*2) / 8 bytes
    static const size_t LANES = RATE / 8;

    uint64_t st[25];
    memset(st, 0, sizeof(st));

    // ---- Absorb full rate-sized blocks ----
    while (in_len >= RATE) {
        for (size_t i = 0; i < LANES; ++i) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; ++b)
                lane |= (uint64_t)in[i*8 + b] << (8*b);
            st[i] ^= lane;
        }
        keccakf(st);
        in    += RATE;
        in_len -= RATE;
    }

    // ---- Absorb final partial block with padding ----
    uint8_t tmp[136];
    memset(tmp, 0, RATE);
    memcpy(tmp, in, in_len);
    tmp[in_len]    = 0x01;          // Ethereum keccak256 padding (NOT 0x06 / SHA3)
    tmp[RATE - 1] |= 0x80;         // set high bit of last byte

    for (size_t i = 0; i < LANES; ++i) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; ++b)
            lane |= (uint64_t)tmp[i*8 + b] << (8*b);
        st[i] ^= lane;
    }
    keccakf(st);

    // ---- Squeeze: extract first 32 bytes (256 bits) ----
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b)
            out[i*8 + b] = (uint8_t)(st[i] >> (8*b));
    }
}

// ---------------------------------------------------------------------------
// C++ helpers
// ---------------------------------------------------------------------------
std::string keccak256_hex(const std::string& data)
{
    uint8_t digest[32];
    keccak256_raw(reinterpret_cast<const uint8_t*>(data.data()), data.size(), digest);

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned)digest[i];
    return oss.str();
}

std::string keccak256_0x(const std::string& data)
{
    return "0x" + keccak256_hex(data);
}
