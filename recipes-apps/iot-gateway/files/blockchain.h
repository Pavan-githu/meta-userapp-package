#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <string>

struct FirmwareDetails {
    std::string version;
    std::string deviceClass;
    std::string sha256;
    std::string size;  // Changed to string for large numbers
    std::string artifact;
    std::string signature;
    std::string publicKey;
    long releasedAt;
};

FirmwareDetails getFirmwareDetails(const std::string& version);
bool registerFirmware(const FirmwareDetails& details);

#endif // BLOCKCHAIN_H
