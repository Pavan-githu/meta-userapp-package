#ifndef BLOCKCHAIN_LOGGER_H
#define BLOCKCHAIN_LOGGER_H

/**
 * blockchain_logger.h  –  IoT authentication event logger for Ethereum
 *
 * Each authentication event (password attempt, OTP dispatch, OTP result,
 * account lockout) is recorded as an immutable transaction on an Ethereum-
 * compatible blockchain via JSON-RPC.
 *
 * ─── HOW IT LINKS OTP / USER / RPi3 WITH BLOCKCHAIN ────────────────────────
 *
 *  1. USER IDENTITY ON-CHAIN (privacy-preserving)
 *     The username is never stored in plaintext on-chain.
 *     Instead every event records keccak256(username) as a bytes32 field.
 *     This lets the contract correlate events per user without revealing the
 *     username to blockchain observers.
 *
 *  2. SESSION CORRELATION
 *     A random 256-bit session_id is created at the password-check step and
 *     is included in every subsequent on-chain event for this login attempt
 *     (OTP_SENT, OTP_SUCCESS / OTP_FAIL).  This links the full flow:
 *       LOGIN_ATTEMPT → OTP_SENT → OTP_SUCCESS/FAIL
 *     in an auditable chain of evidence.
 *
 *  3. DISTRIBUTED FAIL-COUNT & LOCKOUT
 *     The smart contract (IoTAuthLog.sol) tracks how many OTP_FAIL events
 *     the device has emitted for a given user hash.  After MAX_OTP_FAILS (3)
 *     failures the user is locked on-chain.  Even if the RPi3 is rebooted or
 *     its local state is wiped, the lockout persists in the blockchain.
 *     The RPi3 checks isLocked() before each OTP verification attempt.
 *
 *  4. IMMUTABLE AUDIT TRAIL
 *     Every auth event is stored in the contract's events[] array and emitted
 *     as an AuthLogged event.  This log can be queried off-chain by admins,
 *     SIEM systems, or compliance tools via eth_getLogs.
 *
 *  5. NON-REPUDIATION
 *     Each transaction is signed by the RPi3 device's Ethereum account and
 *     timestamped by block.timestamp.  An attacker cannot retroactively alter
 *     or delete a logged event.
 *
 * ─── NETWORK / RPC SETUP ────────────────────────────────────────────────────
 *  Development:  run `npx hardhat node` on a local machine; point rpc_url to
 *                "http://<server-ip>:8545".  The first Hardhat account is
 *                auto-unlocked and can be used as device_addr.
 *  Production:   use a private Ethereum network (e.g. Hyperledger Besu) or a
 *                permissioned sidechain.  The device account should be managed
 *                by a hardware security module (HSM) or secure enclave; replace
 *                eth_sendTransaction with eth_sendRawTransaction + offline signing.
 *
 * ─── DEPENDENCIES ──────────────────────────────────────────────────────────
 *  libcurl  – HTTPS/HTTP JSON-RPC transport
 *  keccak256.h – Ethereum keccak256 for username hashing
 */

#include <string>
#include <cstdint>
#include <ctime>
#include <deque>
#include <pthread.h>

class BlockchainLogger {
public:
    // Must match the EventType enum in IoTAuthLog.sol
    enum EventType : uint8_t {
        LOGIN_ATTEMPT = 0,   // password phase started
        OTP_SENT      = 1,   // password OK, OTP code dispatched to user
        OTP_SUCCESS   = 2,   // correct OTP entered – session granted
        OTP_FAIL      = 3,   // wrong OTP entered
        LOCKOUT       = 4,   // user locked after too many OTP failures
        LOGIN_FAIL    = 5    // wrong password
    };

    /**
     * @param rpc_url        Ethereum JSON-RPC endpoint.
     *                       Local:  "http://127.0.0.1:8545"
     *                       Sepolia:"https://sepolia.infura.io/v3/<API_KEY>"
     * @param contract_addr  Deployed IoTAuthLog contract address ("0x...")
     * @param device_addr    Ethereum account for this RPi3 device ("0x...")
     *                       Must be unlocked on the connected node.
     * @param chain_id       1=mainnet, 11155111=Sepolia, 1337=local Hardhat
     */
    BlockchainLogger(const std::string& rpc_url,
                     const std::string& contract_addr,
                     const std::string& device_addr,
                     uint64_t chain_id = 1337);

    ~BlockchainLogger();

    // Non-copyable
    BlockchainLogger(const BlockchainLogger&)            = delete;
    BlockchainLogger& operator=(const BlockchainLogger&) = delete;

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /**
     * Log an auth event.
     *
     * If the blockchain node is reachable the event is sent immediately and
     * the transaction hash is returned.  If the node is unreachable the event
     * is queued in memory (with the current wall-clock timestamp) and will be
     * replayed automatically by the background flush thread as soon as
     * connectivity is restored.  Auth is NEVER blocked by this call.
     *
     * @param username     Plaintext username (hashed before sending to chain)
     * @param event_type   See EventType enum
     * @param session_hex  64-hex-char session ID (32 bytes, no "0x" prefix)
     * @return             Transaction hash on immediate success; "" if queued
     *                     or on permanent failure.
     */
    std::string logEvent(const std::string& username,
                         EventType event_type,
                         const std::string& session_hex);

    /**
     * Attempt to send all queued (offline) events to the blockchain in
     * the order they were originally generated.  Called automatically by
     * the background flush thread; exposed publicly for testing.
     * Returns the number of events successfully flushed.
     */
    int flushPendingEvents();

    /** Number of events currently waiting in the offline queue. */
    size_t pendingCount() const;

    /**
     * Query the contract: is this user locked out on-chain?
     * Returns false if the blockchain is unreachable (fail-open: the local
     * fail counter in PendingOTP is the backup lockout mechanism).
     */
    bool isUserLocked(const std::string& username);

    /** Returns true if the initial connectivity probe succeeded. */
    bool isAvailable() const { return available_; }

    /**
     * Live connectivity check — probes the node right now.
     * Faster than a full transaction: uses eth_blockNumber (view call).
     * Use this before each login step to detect mid-session VPS failure.
     *
     * @param error_out  Populated with a human-readable reason on failure.
     * @return true if node is reachable and responding.
     */
    bool checkConnectivity(std::string& error_out) const;

    /**
     * Human-readable status string for display in the web UI.
     * Returns e.g. "Connected (block #21847392)" or "Unreachable: timeout".
     */
    std::string getStatusString() const;

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    /**
     * Compute keccak256(username) and return as "0x" + 64 hex chars.
     * The same hash is computed on-chain in any Solidity that does
     *   keccak256(abi.encodePacked(username))
     * so a verified match can be done off-chain for auditing.
     */
    static std::string hashUsername(const std::string& username);

    /**
     * Generate a cryptographically random 256-bit session ID.
     * Returns 64 lowercase hex chars (no "0x"), or "" on error.
     */
    static std::string generateSessionId();

private:
    // -----------------------------------------------------------------------
    // Offline event queue — holds events that could not be sent immediately
    // because the blockchain node was unreachable at the time of the call.
    // Events are replayed in FIFO order by flushPendingEvents().
    // -----------------------------------------------------------------------
    struct PendingEvent {
        std::string  username;      // plaintext (hashed just before sending)
        EventType    event_type;
        std::string  session_hex;   // 64-hex session ID
        std::time_t  queued_at;     // wall-clock time the event was generated
    };

    std::deque<PendingEvent>   pending_queue_;   // FIFO offline event buffer
    static const size_t        MAX_QUEUE = 500;  // cap to avoid unbounded growth

    // Background thread that periodically checks connectivity and flushes queue
    pthread_t        flush_thread_;
    bool             flush_thread_running_;
    static void*     flushThreadFunc(void* arg);

    std::string      rpc_url_;
    std::string      contract_addr_;
    std::string      device_addr_;
    uint64_t         chain_id_;
    bool             available_;
    mutable pthread_mutex_t mutex_;

    // Function selectors (keccak256 of signature, first 4 bytes)
    std::string sel_logEvent_;    // logEvent(bytes32,uint8,bytes32)
    std::string sel_isLocked_;    // isLocked(bytes32)

    // HTTP JSON-RPC POST using libcurl; returns raw response body or ""
    std::string jsonRPC(const std::string& body) const;

    // Extract "result" field from JSON-RPC response (returns raw value string)
    static std::string extractResult(const std::string& json);

    // Returns true if the response contains an "error" field
    static bool hasError(const std::string& json);

    // Build ABI-encoded call data for logEvent(bytes32,uint8,bytes32)
    std::string abiEncodeLogEvent(const std::string& user_hash_0x,
                                  uint8_t            event_type,
                                  const std::string& session_hex) const;

    // Build ABI-encoded call data for isLocked(bytes32)
    std::string abiEncodeIsLocked(const std::string& user_hash_0x) const;

    // Pad hex string to 64 hex chars (32 bytes) by left-padding with zeros
    static std::string leftPad32(const std::string& hex);

    // Pad hex string to 64 hex chars (32 bytes) by right-padding with zeros
    static std::string rightPad32(const std::string& hex);
};

#endif // BLOCKCHAIN_LOGGER_H
