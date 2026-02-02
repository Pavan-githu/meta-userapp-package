# Blockchain Firmware Fetching - C++ Implementation Guide

## Overview

This guide explains how the Raspberry Pi C++ code fetches firmware metadata from your deployed Kaleido blockchain smart contract.

## Architecture

```
┌─────────────────────┐
│  Raspberry Pi       │
│  (C++ Application)  │
└──────────┬──────────┘
           │
           │ HTTP JSON-RPC
           │ (Basic Auth)
           ▼
┌─────────────────────┐
│  Kaleido Ethereum   │
│  RPC Endpoint       │
└──────────┬──────────┘
           │
           │ Smart Contract Call
           │
           ▼
┌─────────────────────┐
│ FirmwareRegistry    │
│ Smart Contract      │
│ 0x0605defbe6e45e... │
└─────────────────────┘
```

## How It Works

### 1. **Smart Contract Function**

The Solidity contract has a getter function:
```solidity
function getFirmwareDetails(string memory version) 
    public view returns (
        string memory version,
        string memory deviceClass,
        string memory sha256Hash,
        string memory size,
        string memory artifact,
        string memory signature,
        string memory publicKey,
        uint256 releasedAt
    )
```

### 2. **C++ Implementation Steps**

#### Step 1: Encode the Function Call

```cpp
// Function selector for getFirmwareDetails(string)
// Calculated as: keccak256("getFirmwareDetails(string)")[:4]
std::string functionSelector = "9b0d0394";

// Encode the string parameter (version) using Solidity ABI encoding
std::string encodedParams = encodeStringParam("1.4.2");

// Combine selector + encoded parameters
std::string data = "0x" + functionSelector + encodedParams;
```

**ABI Encoding for Strings:**
- Offset to string data (32 bytes)
- Length of string (32 bytes)
- String data padded to 32-byte chunks

Example for "1.4.2":
```
0x9b0d0394                                                      # Function selector
0000000000000000000000000000000000000000000000000000000000000020 # Offset (32)
0000000000000000000000000000000000000000000000000000000000000005 # Length (5)
312e342e32000000000000000000000000000000000000000000000000000000 # "1.4.2" in hex
```

#### Step 2: Call the Contract via JSON-RPC

```cpp
// Prepare eth_call request
nlohmann::json params = nlohmann::json::array();
params.push_back({
    {"to", "0x0605defbe6e45e13a77cfca308023e7086cae496"},  // Contract address
    {"data", data}  // Encoded function call
});
params.push_back("latest");  // Block parameter

// Send JSON-RPC request
std::string response = callKaleidoRPC("eth_call", params);
```

**JSON-RPC Request Format:**
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [
    {
      "to": "0x0605defbe6e45e13a77cfca308023e7086cae496",
      "data": "0x9b0d0394..."
    },
    "latest"
  ],
  "id": 1
}
```

#### Step 3: Decode the Response

The response is a hex-encoded ABI-formatted tuple:

```cpp
// Response format:
// {
//   "jsonrpc": "2.0",
//   "id": 1,
//   "result": "0x0000000000000000000000000000000000000000000000000000000000000100..."
// }

// Parse the hex result
std::string result = respJson["result"];  // Remove 0x prefix

// Decode tuple fields:
// - First 8 x 32 bytes are offsets to each string
// - Last 32 bytes is uint256 releasedAt
// - At each offset, read: length (32 bytes) + data

// Extract strings from their offsets
details.version = extractString(offset1);
details.deviceClass = extractString(offset2);
// ... etc
```

#### Step 4: Display Results

```cpp
std::cout << "Version: " << details.version << std::endl;
std::cout << "SHA256: " << details.sha256Hash << std::endl;
// Verify SHA256 matches your local firmware file!
```

## Configuration

### Update blockchain.cpp with Your Settings

```cpp
const std::string RPC_URL = "https://u0xwp2ia0h-u0r1t5x0pu-rpc.us0-aws.kaleido.io/";
const std::string RPC_USER = "u0x1lkfgig";
const std::string RPC_PASSWORD = "Mmnn1OYEnHBCJ1D9mM8wy_vbfxsG6FaJPYdu4GScJYU";
const std::string CONTRACT_ADDRESS = "0x0605defbe6e45e13a77cfca308023e7086cae496";
```

## Testing

### Option 1: Standalone Test Program

```bash
cd /home/pg3930/capstone1/raspberrypi3/poky/meta-userapp-package/recipes-apps/iot-gateway/files

# Install dependencies (if not already installed)
sudo apt-get update
sudo apt-get install -y libcurl4-openssl-dev nlohmann-json3-dev

# Build test program
make -f Makefile.test

# Run test
./test_blockchain 1.4.2
```

### Option 2: Integrated in IoT Gateway

The blockchain fetching is integrated into `main.cpp` as a separate thread:

```cpp
void* blockchainOperationsThread(void* arg) {
    std::string firmware_version_to_check = "1.4.2";
    FirmwareDetails details = getFirmwareDetails(firmware_version_to_check);
    
    if (!details.version.empty()) {
        // Print firmware details
        // Verify SHA256 hash
        // Check signature
    }
    
    return NULL;
}
```

Build the full IoT Gateway application with Yocto to include blockchain functionality.

## Expected Output

```
🔗 Connecting to Kaleido Blockchain...
📦 Fetching firmware details for version: 1.4.2

Calling contract at: 0x0605defbe6e45e13a77cfca308023e7086cae496
Function data: 0x9b0d0394...
Response: {"jsonrpc":"2.0","id":1,"result":"0x00000..."}

╔════════════════════════════════════════════════════════╗
║      FIRMWARE DETAILS FROM BLOCKCHAIN                  ║
╠════════════════════════════════════════════════════════╣
║ Version:      1.4.2                                    ║
║ Device Class: raspberrypi3                             ║
╠════════════════════════════════════════════════════════╣
║ SHA256 Hash:                                           ║
║   3f398ade9f79a5c6bf008d9590f65a54adf4648a4046bccf... ║
╠════════════════════════════════════════════════════════╣
║ Size:         95816997 bytes                           ║
║ Artifact:     core-image-dual-rootfs-raspberrypi3-... ║
╠════════════════════════════════════════════════════════╣
║ Signature:    [HSM signature from Kaleido]            ║
║ Public Key:   [Vendor public key]                     ║
╠════════════════════════════════════════════════════════╣
║ Released At:  2025-01-28 00:45:00                     ║
╚════════════════════════════════════════════════════════╝

✅ Successfully retrieved firmware metadata from blockchain
```

## Security Verification Flow

```
1. Fetch firmware metadata from blockchain
   ↓
2. Download firmware file from artifact location
   ↓
3. Calculate SHA256 hash of downloaded file
   ↓
4. Compare with sha256Hash from blockchain
   ✓ Match? → Continue
   ✗ Mismatch? → Reject (tampered file!)
   ↓
5. Verify signature using publicKey
   ✓ Valid? → Proceed with firmware update
   ✗ Invalid? → Reject (unauthorized firmware!)
```

## Key Functions

### `getFirmwareDetails(const std::string& version)`

**Purpose:** Fetch firmware metadata from blockchain for a specific version.

**Returns:** `FirmwareDetails` struct containing all metadata, or empty struct if not found.

**Example Usage:**
```cpp
FirmwareDetails details = getFirmwareDetails("1.4.2");
if (!details.version.empty()) {
    // Firmware found
    std::cout << "SHA256: " << details.sha256Hash << std::endl;
    
    // Verify your local firmware matches this hash
    // verifyFirmwareIntegrity(firmware_file, details.sha256Hash);
} else {
    // Firmware not found or error
    std::cerr << "Firmware version not found" << std::endl;
}
```

### Helper Functions

- **`encodeStringParam()`** - Encodes strings for Solidity ABI
- **`callKaleidoRPC()`** - Makes JSON-RPC calls with Basic Auth
- **`hexToString()`** - Converts hex data to readable strings
- **`hexToUint64()`** - Converts hex numbers to integers

## Dependencies

### Required Libraries

```bash
# Ubuntu/Debian
sudo apt-get install libcurl4-openssl-dev nlohmann-json3-dev

# For Yocto build, add to recipe:
# DEPENDS += "curl nlohmann-json"
```

### Headers Required

```cpp
#include <curl/curl.h>          // For HTTP requests
#include <nlohmann/json.hpp>     // For JSON parsing
#include <string>
#include <sstream>
#include <iomanip>
```

## Troubleshooting

### Issue: "Empty response from blockchain"

**Solution:** Check network connectivity and RPC URL
```bash
curl -u u0x1lkfgig:Mmnn1OYEnHBCJ1D9mM8wy_vbfxsG6FaJPYdu4GScJYU \
  -X POST https://u0xwp2ia0h-u0r1t5x0pu-rpc.us0-aws.kaleido.io/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Issue: "No firmware found for version"

**Causes:**
1. Firmware not uploaded to blockchain yet
2. Wrong version string (check exact spelling)
3. Contract address incorrect

**Solution:** Upload firmware metadata first:
```bash
cd /home/pg3930/capstone1/raspberrypi3/blockchain
node upload.js <firmware_file> <version> <device_class>
```

### Issue: Authentication errors (401)

**Solution:** Verify RPC credentials in blockchain.cpp match your Kaleido app credentials

## Next Steps

1. **Upload Firmware Metadata:** Use `upload.js` to register firmware on blockchain
2. **Test Fetching:** Run `test_blockchain` to verify data retrieval
3. **Integrate Verification:** Add SHA256 verification and signature checking
4. **Build for Raspberry Pi:** Compile with Yocto for target device

## Contract Information

- **Contract Address:** `0x0605defbe6e45e13a77cfca308023e7086cae496`
- **Network:** Kaleido Ethereum (Private)
- **RPC Endpoint:** `https://u0xwp2ia0h-u0r1t5x0pu-rpc.us0-aws.kaleido.io/`
- **Explorer:** `https://u0xwp2ia0h-u0r1t5x0pu-explorer.us0-aws.kaleido.io/`

View your contract in the explorer by visiting:
https://u0xwp2ia0h-u0r1t5x0pu-explorer.us0-aws.kaleido.io/address/0x0605defbe6e45e13a77cfca308023e7086cae496
