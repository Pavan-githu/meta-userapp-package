/**
 * blockchain_logger.cpp  –  Ethereum JSON-RPC auth event logger
 *
 * Uses libcurl for HTTP transport and implements minimal Ethereum ABI encoding
 * to call the IoTAuthLog smart contract.
 *
 * Transport model:
 *   Write calls: eth_sendTransaction  (requires device_addr unlocked on node)
 *   Read  calls: eth_call             (no signing needed – view functions)
 *
 * For production deployment with a locked account, replace eth_sendTransaction
 * with offline transaction signing + eth_sendRawTransaction.  The ABI encoding
 * layer (abiEncodeLogEvent / abiEncodeIsLocked) is reusable in that path.
 */

#include "blockchain_logger.h"
#include "keccak256.h"

#include <curl/curl.h>
#include <openssl/rand.h>

#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <unistd.h>   // sleep()

// ---------------------------------------------------------------------------
// libcurl write-callback: accumulates response body into a std::string
// ---------------------------------------------------------------------------
static size_t curlWrite(void* ptr, size_t size, size_t nmemb, std::string* out)
{
    out->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
BlockchainLogger::BlockchainLogger(const std::string& rpc_url,
                                   const std::string& contract_addr,
                                   const std::string& device_addr,
                                   uint64_t chain_id)
    : rpc_url_(rpc_url),
      contract_addr_(contract_addr),
      device_addr_(device_addr),
      chain_id_(chain_id),
      available_(false),
      flush_thread_running_(false)
{
    pthread_mutex_init(&mutex_, nullptr);

    // Pre-compute function selectors using keccak256 at startup
    // Selector = first 4 bytes (8 hex chars) of keccak256(signature)
    std::string h1 = keccak256_hex("logEvent(bytes32,uint8,bytes32)");
    sel_logEvent_  = "0x" + h1.substr(0, 8);

    std::string h2 = keccak256_hex("isLocked(bytes32)");
    sel_isLocked_  = "0x" + h2.substr(0, 8);

    std::cout << "[Blockchain] logEvent selector : " << sel_logEvent_ << "\n";
    std::cout << "[Blockchain] isLocked selector : " << sel_isLocked_ << "\n";

    // Connectivity probe
    std::string probe = R"({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1})";
    std::string resp  = jsonRPC(probe);
    if (!resp.empty() && resp.find("\"result\"") != std::string::npos) {
        available_ = true;
        std::cout << "[Blockchain] Connected to RPC: " << rpc_url_ << "\n";
    } else {
        std::cerr << "[Blockchain] WARNING: Cannot reach " << rpc_url_
                  << " — events will be queued and replayed when chain returns\n";
    }

    // Start background flush thread — wakes every 30 s to drain the queue
    flush_thread_running_ = true;
    pthread_create(&flush_thread_, nullptr, &BlockchainLogger::flushThreadFunc, this);
}

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------
BlockchainLogger::~BlockchainLogger()
{
    // Signal flush thread to stop and wait for it
    flush_thread_running_ = false;
    pthread_join(flush_thread_, nullptr);
    pthread_mutex_destroy(&mutex_);
}

// ---------------------------------------------------------------------------
// jsonRPC  –  POST a JSON-RPC body and return the raw response
// ---------------------------------------------------------------------------
std::string BlockchainLogger::jsonRPC(const std::string& body) const
{
    pthread_mutex_lock(&mutex_);

    CURL* curl = curl_easy_init();
    if (!curl) {
        pthread_mutex_unlock(&mutex_);
        return "";
    }

    std::string response;
    struct curl_slist* hdrs = curl_slist_append(nullptr, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL,           rpc_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        5L);     // 5-second timeout
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,       1L);     // thread-safe

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    pthread_mutex_unlock(&mutex_);

    if (rc != CURLE_OK) {
        std::cerr << "[Blockchain] curl error: " << curl_easy_strerror(rc) << "\n";
        return "";
    }
    return response;
}

// ---------------------------------------------------------------------------
// extractResult  –  pull the "result" string value from a JSON-RPC response
// ---------------------------------------------------------------------------
std::string BlockchainLogger::extractResult(const std::string& json)
{
    // Look for "result":"<value>" or "result":<value>
    const std::string key = "\"result\":";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";

    pos += key.size();
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        // Quoted string value
        ++pos;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    } else {
        // Unquoted value (number, bool, null)
        size_t end = json.find_first_of(",}\n", pos);
        if (end == std::string::npos) end = json.size();
        return json.substr(pos, end - pos);
    }
}

// ---------------------------------------------------------------------------
// hasError
// ---------------------------------------------------------------------------
bool BlockchainLogger::hasError(const std::string& json)
{
    return json.find("\"error\"") != std::string::npos;
}

// ---------------------------------------------------------------------------
// leftPad32  –  left-pad hex string to 64 chars (uint256 / address encoding)
// ---------------------------------------------------------------------------
std::string BlockchainLogger::leftPad32(const std::string& hex)
{
    std::string h = hex;
    // Strip leading 0x if present
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        h = h.substr(2);
    if (h.size() > 64) h = h.substr(h.size() - 64);  // truncate overflow
    return std::string(64 - h.size(), '0') + h;
}

// ---------------------------------------------------------------------------
// rightPad32  –  right-pad hex string to 64 chars (bytesN encoding)
// ---------------------------------------------------------------------------
std::string BlockchainLogger::rightPad32(const std::string& hex)
{
    std::string h = hex;
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        h = h.substr(2);
    if (h.size() > 64) h = h.substr(0, 64);          // truncate overflow
    return h + std::string(64 - h.size(), '0');
}

// ---------------------------------------------------------------------------
// abiEncodeLogEvent
//   logEvent(bytes32 userHash, uint8 eventType, bytes32 sessionId)
//
//   ABI layout (EIP-4):
//     [0:4]    function selector  (4 bytes)
//     [4:36]   bytes32 userHash   (32 bytes, NOT padded – it is already 32)
//     [36:68]  uint8  eventType   (32 bytes, left-padded)
//     [68:100] bytes32 sessionId  (32 bytes, NOT padded – already 32)
// ---------------------------------------------------------------------------
std::string BlockchainLogger::abiEncodeLogEvent(const std::string& user_hash_0x,
                                                 uint8_t event_type,
                                                 const std::string& session_hex) const
{
    // user_hash_0x is "0x" + 64 hex chars from keccak256
    std::string uh = user_hash_0x;
    if (uh.size() >= 2 && uh[0] == '0' && uh[1] == 'x') uh = uh.substr(2);
    uh = rightPad32(uh);  // bytes32 is right-padded (it should already be 64 chars)

    // uint8 event type: left-padded to 32 bytes
    std::string ev = leftPad32(
        [&]() -> std::string {
            char buf[3]; std::snprintf(buf, sizeof(buf), "%02x", event_type);
            return std::string(buf);
        }()
    );

    // session_hex is 64 hex chars (32 bytes) — bytes32, right-padded
    std::string sid = rightPad32(session_hex);

    // Selector is stored without the leading "0x"
    std::string sel = sel_logEvent_;
    if (sel.size() >= 2 && sel[0] == '0') sel = sel.substr(2);

    return "0x" + sel + uh + ev + sid;
}

// ---------------------------------------------------------------------------
// abiEncodeIsLocked
//   isLocked(bytes32 userHash)
// ---------------------------------------------------------------------------
std::string BlockchainLogger::abiEncodeIsLocked(const std::string& user_hash_0x) const
{
    std::string uh = user_hash_0x;
    if (uh.size() >= 2 && uh[0] == '0' && uh[1] == 'x') uh = uh.substr(2);
    uh = rightPad32(uh);

    std::string sel = sel_isLocked_;
    if (sel.size() >= 2 && sel[0] == '0') sel = sel.substr(2);

    return "0x" + sel + uh;
}

// ---------------------------------------------------------------------------
// hashUsername
// ---------------------------------------------------------------------------
std::string BlockchainLogger::hashUsername(const std::string& username)
{
    return keccak256_0x(username);
}

// ---------------------------------------------------------------------------
// generateSessionId  –  returns 64 hex chars (32 random bytes)
// ---------------------------------------------------------------------------
std::string BlockchainLogger::generateSessionId()
{
    uint8_t buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1) return "";

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned)buf[i];
    return oss.str();
}

// ---------------------------------------------------------------------------
// flushThreadFunc — background thread: checks connectivity every 30 s and
//   drains the pending queue when the chain is reachable.
// ---------------------------------------------------------------------------
void* BlockchainLogger::flushThreadFunc(void* arg)
{
    BlockchainLogger* self = static_cast<BlockchainLogger*>(arg);
    while (self->flush_thread_running_) {
        sleep(30);
        if (!self->flush_thread_running_) break;

        std::string err;
        bool reachable = self->checkConnectivity(err);

        pthread_mutex_lock(&self->mutex_);
        self->available_ = reachable;
        size_t qsize = self->pending_queue_.size();
        pthread_mutex_unlock(&self->mutex_);

        if (reachable && qsize > 0) {
            std::cout << "[Blockchain] Chain reachable — flushing "
                      << qsize << " queued event(s)\n";
            self->flushPendingEvents();
        } else if (!reachable && qsize > 0) {
            std::cerr << "[Blockchain] Still unreachable — "
                      << qsize << " event(s) remain queued\n";
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// flushPendingEvents — send all queued events to chain in FIFO order,
//   preserving their original wall-clock timestamps in the log output.
// ---------------------------------------------------------------------------
int BlockchainLogger::flushPendingEvents()
{
    int flushed = 0;
    while (true) {
        pthread_mutex_lock(&mutex_);
        if (pending_queue_.empty()) {
            pthread_mutex_unlock(&mutex_);
            break;
        }
        PendingEvent ev = pending_queue_.front();
        pthread_mutex_unlock(&mutex_);

        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S",
                      std::localtime(&ev.queued_at));

        std::string user_hash = hashUsername(ev.username);
        std::string calldata  = abiEncodeLogEvent(user_hash,
                                                  static_cast<uint8_t>(ev.event_type),
                                                  ev.session_hex);

        std::ostringstream body;
        body << R"({"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{)"
             << R"("from":")" << device_addr_ << R"(",)"
             << R"("to":")"   << contract_addr_ << R"(",)"
             << R"("gas":"0x30d40",)"
             << R"("data":")" << calldata << R"("}],"id":2})";

        std::string resp = jsonRPC(body.str());
        if (resp.empty() || hasError(resp)) {
            // Chain went away again — stop, keep event at front of queue
            std::cerr << "[Blockchain] Flush interrupted (chain unreachable) — "
                      << pending_queue_.size() << " event(s) remain queued\n";
            pthread_mutex_lock(&mutex_);
            available_ = false;
            pthread_mutex_unlock(&mutex_);
            break;
        }

        // Remove successfully sent event from queue
        pthread_mutex_lock(&mutex_);
        if (!pending_queue_.empty())
            pending_queue_.pop_front();
        pthread_mutex_unlock(&mutex_);

        std::string txhash = extractResult(resp);
        std::cout << "[Blockchain] Flushed queued event (originally at " << ts << ")"
                  << " user=" << user_hash.substr(0, 10) << "..."
                  << " event=" << static_cast<int>(ev.event_type)
                  << " tx=" << txhash << "\n";
        ++flushed;
    }
    return flushed;
}

// ---------------------------------------------------------------------------
// pendingCount
// ---------------------------------------------------------------------------
size_t BlockchainLogger::pendingCount() const
{
    pthread_mutex_lock(&mutex_);
    size_t n = pending_queue_.size();
    pthread_mutex_unlock(&mutex_);
    return n;
}

// ---------------------------------------------------------------------------
// logEvent
// ---------------------------------------------------------------------------
std::string BlockchainLogger::logEvent(const std::string& username,
                                       EventType event_type,
                                       const std::string& session_hex)
{
    // Check current availability under lock
    pthread_mutex_lock(&mutex_);
    bool currently_available = available_;
    pthread_mutex_unlock(&mutex_);

    if (!currently_available) {
        // Queue the event with the current wall-clock timestamp so the audit
        // trail preserves WHEN it actually occurred, not when it was sent.
        pthread_mutex_lock(&mutex_);
        if (pending_queue_.size() < MAX_QUEUE) {
            PendingEvent ev;
            ev.username    = username;
            ev.event_type  = event_type;
            ev.session_hex = session_hex;
            ev.queued_at   = std::time(nullptr);
            pending_queue_.push_back(ev);
            std::cerr << "[Blockchain] Node unreachable — event queued ("
                      << pending_queue_.size() << " pending)\n";
        } else {
            std::cerr << "[Blockchain] Queue full (" << MAX_QUEUE
                      << ") — oldest event dropped. Check chain connectivity.\n";
        }
        pthread_mutex_unlock(&mutex_);
        return "";   // auth is NOT blocked
    }

    std::string user_hash = hashUsername(username);
    std::string calldata  = abiEncodeLogEvent(user_hash,
                                               static_cast<uint8_t>(event_type),
                                               session_hex);

    // gas = 0x30d40 = 200 000
    std::ostringstream body;
    body << R"({"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{)"
         << R"("from":")" << device_addr_ << R"(",)"
         << R"("to":")"   << contract_addr_ << R"(",)"
         << R"("gas":"0x30d40",)"
         << R"("data":")" << calldata << R"("}],"id":2})";

    std::string resp = jsonRPC(body.str());
    if (resp.empty() || hasError(resp)) {
        // Send failed mid-flight — queue for retry and mark unavailable
        std::cerr << "[Blockchain] logEvent send failed — queueing for retry\n";
        pthread_mutex_lock(&mutex_);
        available_ = false;
        if (pending_queue_.size() < MAX_QUEUE) {
            PendingEvent ev;
            ev.username    = username;
            ev.event_type  = event_type;
            ev.session_hex = session_hex;
            ev.queued_at   = std::time(nullptr);
            pending_queue_.push_back(ev);
        }
        pthread_mutex_unlock(&mutex_);
        return "";
    }

    std::string txhash = extractResult(resp);
    std::cout << "[Blockchain] logEvent txhash=" << txhash
              << " user=" << user_hash.substr(0, 10) << "..."
              << " event=" << static_cast<int>(event_type) << "\n";
    return txhash;
}

// ---------------------------------------------------------------------------
// checkConnectivity  –  live probe, called before each login step
// ---------------------------------------------------------------------------
bool BlockchainLogger::checkConnectivity(std::string& error_out) const
{
    std::string probe =
        R"({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":99})";
    std::string resp = jsonRPC(probe);

    if (resp.empty()) {
        error_out = "No response from blockchain node (" + rpc_url_ + "). "
                    "Check that the Ethereum node is running on the VPS.";
        return false;
    }
    if (hasError(resp)) {
        error_out = "Blockchain node returned error. Response: " + resp;
        return false;
    }
    if (resp.find("\"result\"") == std::string::npos) {
        error_out = "Unexpected response from node: " + resp;
        return false;
    }
    error_out = "";
    return true;
}

// ---------------------------------------------------------------------------
// getStatusString  –  human-readable status for web UI
// ---------------------------------------------------------------------------
std::string BlockchainLogger::getStatusString() const
{
    std::string probe =
        R"({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":99})";
    std::string resp = jsonRPC(probe);

    if (resp.empty())
        return "Unreachable — no response from " + rpc_url_;

    std::string block = extractResult(resp);
    if (block.empty() || hasError(resp))
        return "Unreachable — node error";

    // Convert hex block number to decimal
    uint64_t blockNum = 0;
    std::string hex = block;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);
    for (char c : hex) {
        blockNum <<= 4;
        if (c >= '0' && c <= '9') blockNum |= (c - '0');
        else if (c >= 'a' && c <= 'f') blockNum |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') blockNum |= (c - 'A' + 10);
    }

    return "Connected  |  Block #" + std::to_string(blockNum) +
           "  |  Node: " + rpc_url_;
}

// ---------------------------------------------------------------------------
// isUserLocked
// ---------------------------------------------------------------------------
bool BlockchainLogger::isUserLocked(const std::string& username)
{
    if (!available_) return false;   // fail-open when blockchain unreachable

    std::string user_hash = hashUsername(username);
    std::string calldata  = abiEncodeIsLocked(user_hash);

    std::ostringstream body;
    body << R"({"jsonrpc":"2.0","method":"eth_call","params":[{)"
         << R"("to":")" << contract_addr_ << R"(",)"
         << R"("data":")" << calldata << R"("},"latest"],"id":3})";

    std::string resp = jsonRPC(body.str());
    if (resp.empty() || hasError(resp)) {
        std::cerr << "[Blockchain] isUserLocked query failed – assuming unlocked\n";
        return false;
    }

    std::string result = extractResult(resp);  // "0x0" (false) or "0x1..." (true)

    // A locked result will have at least one non-zero nibble after the 0x prefix
    // Standard ABI bool return: 32 zero bytes for false, 32 bytes with last byte = 1 for true
    if (result.size() < 2) return false;
    std::string hex = (result[0] == '0' && (result[1] == 'x' || result[1] == 'X'))
                      ? result.substr(2) : result;

    for (char c : hex)
        if (c != '0') return true;   // any non-zero nibble → true (locked)

    return false;
}
