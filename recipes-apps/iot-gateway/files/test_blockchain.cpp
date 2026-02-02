// Test program to fetch firmware details from Kaleido blockchain
#include "blockchain.h"
#include <iostream>
#include <iomanip>
#include <ctime>

void printFirmwareDetails(const FirmwareDetails& details) {
    if (details.version.empty()) {
        std::cout << "❌ No firmware found or error occurred" << std::endl;
        return;
    }

    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║      FIRMWARE DETAILS FROM BLOCKCHAIN                  ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║ Version:      " << std::setw(40) << std::left << details.version << " ║" << std::endl;
    std::cout << "║ Device Class: " << std::setw(40) << std::left << details.deviceClass << " ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║ SHA256 Hash:                                           ║" << std::endl;
    std::cout << "║   " << std::setw(51) << std::left << details.sha256Hash << " ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║ Size:         " << std::setw(40) << std::left << (details.size + " bytes") << " ║" << std::endl;
    std::cout << "║ Artifact:                                              ║" << std::endl;
    std::cout << "║   " << std::setw(51) << std::left << details.artifact << " ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    
    // Print signature (truncated if too long)
    std::string sig_display = details.signature;
    if (sig_display.length() > 50) {
        sig_display = sig_display.substr(0, 47) + "...";
    }
    std::cout << "║ Signature:                                             ║" << std::endl;
    std::cout << "║   " << std::setw(51) << std::left << sig_display << " ║" << std::endl;
    
    // Print public key (truncated if too long)
    std::string key_display = details.publicKey;
    if (key_display.length() > 50) {
        key_display = key_display.substr(0, 47) + "...";
    }
    std::cout << "║ Public Key:                                            ║" << std::endl;
    std::cout << "║   " << std::setw(51) << std::left << key_display << " ║" << std::endl;
    
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    
    // Convert Unix timestamp to readable date
    std::time_t timestamp = details.releasedAt;
    std::tm* timeinfo = std::localtime(&timestamp);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    std::cout << "║ Released At:  " << std::setw(40) << std::left << buffer << " ║" << std::endl;
    std::cout << "║               " << std::setw(40) << std::left << ("(Unix: " + std::to_string(details.releasedAt) + ")") << " ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::string version = "1.4.2"; // Default version
    
    if (argc > 1) {
        version = argv[1];
    }
    
    std::cout << "🔗 Connecting to Kaleido Blockchain..." << std::endl;
    std::cout << "📦 Fetching firmware details for version: " << version << std::endl;
    std::cout << std::endl;
    
    FirmwareDetails details = getFirmwareDetails(version);
    
    printFirmwareDetails(details);
    
    // Example: Verify firmware integrity
    if (!details.version.empty()) {
        std::cout << "✅ Successfully retrieved firmware metadata from blockchain" << std::endl;
        std::cout << "📝 Next steps:" << std::endl;
        std::cout << "   1. Calculate SHA256 of your local firmware file" << std::endl;
        std::cout << "   2. Compare with blockchain SHA256: " << details.sha256Hash << std::endl;
        std::cout << "   3. Verify signature using public key" << std::endl;
        std::cout << "   4. If verified, proceed with firmware update" << std::endl;
    }
    
    return 0;
}
