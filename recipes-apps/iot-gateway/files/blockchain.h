#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <string>

struct FirmwareDetails {
    std::string version;
    std::string deviceClass;
    std::string sha256;
    std::string artifact;
    std::string signedBy;
    long releasedAt;
};

FirmwareDetails getFirmwareDetails(const std::string& version);

#endif // BLOCKCHAIN_H
