#include "blockchain.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// Kaleido RPC configuration
const std::string RPC_URL = "https://u0xwp2ia0h-u0r1t5x0pu-rpc.us0-aws.kaleido.io/";
const std::string RPC_USER = "u0x1lkfgig";
const std::string RPC_PASSWORD = "Mmnn1OYEnHBCJ1D9mM8wy_vbfxsG6FaJPYdu4GScJYU";
const std::string CONTRACT_ADDRESS = "0x0605defbe6e45e13a77cfca308023e7086cae496";

// Helper function to write curl response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    s->append((char*)contents, newLength);
    return newLength;
}

// Helper function to encode string to hex
std::string stringToHex(const std::string& input) {
    std::stringstream ss;
    for (unsigned char c : input) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

// Helper function to pad hex string to 32 bytes (64 hex chars)
std::string padHex(const std::string& hex, size_t length = 64) {
    if (hex.length() >= length) return hex;
    return std::string(length - hex.length(), '0') + hex;
}

// Helper function to encode string parameter for Solidity
std::string encodeStringParam(const std::string& str) {
    // String encoding: offset (32 bytes) + length (32 bytes) + data (padded to 32 byte chunks)
    std::stringstream ss;
    
    // Calculate offset (0x20 = 32 bytes, standard offset for first dynamic param)
    ss << padHex("20");
    
    // Length of string
    std::stringstream lengthHex;
    lengthHex << std::hex << str.length();
    ss << padHex(lengthHex.str());
    
    // String data in hex, padded to 32 bytes
    std::string hexData = stringToHex(str);
    size_t paddingNeeded = ((hexData.length() + 63) / 64) * 64; // Round up to multiple of 64
    hexData.resize(paddingNeeded, '0');
    ss << hexData;
    
    return ss.str();
}

// Helper function to decode hex string to regular string
std::string hexToString(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        char chr = (char)(int)strtol(byte.c_str(), nullptr, 16);
        if (chr != 0) result.push_back(chr);
    }
    return result;
}

// Helper function to decode uint256 from hex
uint64_t hexToUint64(const std::string& hex) {
    return std::stoull(hex, nullptr, 16);
}

// Function to call Kaleido RPC
std::string callKaleidoRPC(const std::string& method, const nlohmann::json& params) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        nlohmann::json request = {
            {"jsonrpc", "2.0"},
            {"method", method},
            {"params", params},
            {"id", 1}
        };

        std::string jsonStr = request.dump();
        std::string auth = RPC_USER + ":" + RPC_PASSWORD;

        curl_easy_setopt(curl, CURLOPT_URL, RPC_URL.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            return "";
        }
    }

    return readBuffer;
}

FirmwareDetails getFirmwareDetails(const std::string& version) {
    // getFirmwareDetails(string) function signature: 0x9b0d0394
    std::string functionSelector = "9b0d0394";
    std::string encodedParams = encodeStringParam(version);
    std::string data = "0x" + functionSelector + encodedParams;

    std::cout << "Calling contract at: " << CONTRACT_ADDRESS << std::endl;
    std::cout << "Function data: " << data << std::endl;

    nlohmann::json params = nlohmann::json::array();
    params.push_back({
        {"to", CONTRACT_ADDRESS},
        {"data", data}
    });
    params.push_back("latest");

    std::string response = callKaleidoRPC("eth_call", params);

    if (response.empty()) {
        std::cerr << "Empty response from blockchain" << std::endl;
        return {};
    }

    std::cout << "Response: " << response << std::endl;

    try {
        nlohmann::json respJson = nlohmann::json::parse(response);
        
        if (respJson.contains("error")) {
            std::cerr << "Error from blockchain: " << respJson["error"].dump() << std::endl;
            return {};
        }
        
        if (respJson.contains("result")) {
            std::string result = respJson["result"];
            
            if (result == "0x" || result.length() < 10) {
                std::cerr << "No firmware found for version: " << version << std::endl;
                return {};
            }

            // Remove 0x prefix
            if (result.substr(0, 2) == "0x") {
                result = result.substr(2);
            }

            // Decode the tuple result
            // The result is: (string version, string deviceClass, string sha256Hash, 
            //                 string size, string artifact, string signature, 
            //                 string publicKey, uint256 releasedAt)
            
            FirmwareDetails details;
            
            // Parse the dynamic array offsets and data
            // Each 32 bytes (64 hex chars) is one slot
            size_t pos = 0;
            
            // Read offset pointers for each string (8 fields total)
            std::vector<size_t> offsets;
            for (int i = 0; i < 8; i++) {
                std::string offsetHex = result.substr(pos, 64);
                size_t offset = hexToUint64(offsetHex) * 2; // Convert to hex string position
                offsets.push_back(offset);
                pos += 64;
            }
            
            // Helper to extract string at offset
            auto extractString = [&](size_t offset) -> std::string {
                size_t lengthPos = offset;
                std::string lengthHex = result.substr(lengthPos, 64);
                size_t length = hexToUint64(lengthHex);
                size_t dataPos = lengthPos + 64;
                std::string hexData = result.substr(dataPos, length * 2);
                return hexToString(hexData);
            };
            
            // Extract each field
            details.version = extractString(offsets[0]);
            details.deviceClass = extractString(offsets[1]);
            details.sha256Hash = extractString(offsets[2]);
            details.size = extractString(offsets[3]);
            details.artifact = extractString(offsets[4]);
            details.signature = extractString(offsets[5]);
            details.publicKey = extractString(offsets[6]);
            
            // Last field (releasedAt) is uint256, not an offset
            std::string timestampHex = result.substr(pos - 64, 64);
            details.releasedAt = hexToUint64(timestampHex);
            
            return details;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
    }

    return {};
}

// Function to register firmware (call this to upload metadata from Raspberry Pi if needed)
bool registerFirmware(const FirmwareDetails& details) {
    std::cout << "Note: registerFirmware is typically called from the upload script, not from Raspberry Pi" << std::endl;
    std::cout << "This function would require a private key to sign transactions" << std::endl;
    
    // registerFirmware function signature: 0x1234abcd (calculate actual hash)
    // For now, this is a read-only implementation
    // To write data, you need to sign transactions with a private key
    
    return false;
}
