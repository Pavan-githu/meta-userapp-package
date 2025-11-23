#include "certificate.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// ============================================================================
// CertificateManager Implementation
// ============================================================================

CertificateManager::CertificateManager(const std::string& certificate_directory) 
    : cert_dir(certificate_directory) {
    // Set up certificate paths
    root_key_path = cert_dir + "/root-ca.key";
    root_cert_path = cert_dir + "/root-ca.crt";
    server_key_path = cert_dir + "/server.key";
    server_csr_path = cert_dir + "/server.csr";
    server_cert_path = cert_dir + "/server.crt";
    client_key_path = cert_dir + "/client.key";
    client_csr_path = cert_dir + "/client.csr";
    client_cert_path = cert_dir + "/client.crt";
}

bool CertificateManager::executeCommand(const std::string& command) {
    std::cout << "Executing: " << command << std::endl;
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Command failed with exit code: " << result << std::endl;
        return false;
    }
    return true;
}

bool CertificateManager::fileExists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

bool CertificateManager::createDirectory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    
    // Create directory with proper permissions
    if (mkdir(path.c_str(), 0755) != 0) {
        std::cerr << "Failed to create directory: " << path << std::endl;
        return false;
    }
    
    std::cout << "Created directory: " << path << std::endl;
    return true;
}

bool CertificateManager::setupCertificateDirectory() {
    std::cout << "Setting up certificate directory: " << cert_dir << std::endl;
    return createDirectory(cert_dir);
}

bool CertificateManager::generateRootCA(const std::string& subject) {
    std::cout << "\n=== Generating Root CA ===" << std::endl;
    
    if (fileExists(root_key_path) && fileExists(root_cert_path)) {
        std::cout << "Root CA already exists. Skipping generation." << std::endl;
        return true;
    }
    
    // Generate root CA private key
    std::string key_cmd = "openssl genrsa -out " + root_key_path + " 4096 2>/dev/null";
    if (!executeCommand(key_cmd)) {
        return false;
    }
    
    // Generate root CA certificate
    std::string cert_cmd = "openssl req -x509 -new -nodes -key " + root_key_path + 
                          " -sha256 -days 3650 -out " + root_cert_path + 
                          " -subj \"" + subject + "\" 2>/dev/null";
    if (!executeCommand(cert_cmd)) {
        return false;
    }
    
    std::cout << "Root CA generated successfully" << std::endl;
    std::cout << "  Key: " << root_key_path << std::endl;
    std::cout << "  Certificate: " << root_cert_path << std::endl;
    return true;
}

bool CertificateManager::generateServerKey() {
    std::cout << "\n=== Generating Server Key ===" << std::endl;
    
    if (fileExists(server_key_path)) {
        std::cout << "Server key already exists. Skipping generation." << std::endl;
        return true;
    }
    
    std::string cmd = "openssl genrsa -out " + server_key_path + " 4096 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Server key generated: " << server_key_path << std::endl;
    return true;
}

bool CertificateManager::generateServerCSR(const std::string& subject) {
    std::cout << "\n=== Generating Server CSR ===" << std::endl;
    
    if (!fileExists(server_key_path)) {
        std::cerr << "Server key does not exist. Generate key first." << std::endl;
        return false;
    }
    
    std::string cmd = "openssl req -new -key " + server_key_path + 
                     " -out " + server_csr_path + 
                     " -subj \"" + subject + "\" 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Server CSR generated: " << server_csr_path << std::endl;
    return true;
}

bool CertificateManager::signServerCertificate(int validity_days) {
    std::cout << "\n=== Signing Server Certificate ===" << std::endl;
    
    if (!fileExists(root_key_path) || !fileExists(root_cert_path)) {
        std::cerr << "Root CA does not exist. Generate root CA first." << std::endl;
        return false;
    }
    
    if (!fileExists(server_csr_path)) {
        std::cerr << "Server CSR does not exist. Generate CSR first." << std::endl;
        return false;
    }
    
    std::string cmd = "openssl x509 -req -in " + server_csr_path + 
                     " -CA " + root_cert_path + 
                     " -CAkey " + root_key_path + 
                     " -CAcreateserial -out " + server_cert_path + 
                     " -days " + std::to_string(validity_days) + 
                     " -sha256 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Server certificate signed and generated: " << server_cert_path << std::endl;
    return true;
}

bool CertificateManager::generateClientKey() {
    std::cout << "\n=== Generating Client Key ===" << std::endl;
    
    if (fileExists(client_key_path)) {
        std::cout << "Client key already exists. Skipping generation." << std::endl;
        return true;
    }
    
    std::string cmd = "openssl genrsa -out " + client_key_path + " 4096 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Client key generated: " << client_key_path << std::endl;
    return true;
}

bool CertificateManager::generateClientCSR(const std::string& subject) {
    std::cout << "\n=== Generating Client CSR ===" << std::endl;
    
    if (!fileExists(client_key_path)) {
        std::cerr << "Client key does not exist. Generate key first." << std::endl;
        return false;
    }
    
    std::string cmd = "openssl req -new -key " + client_key_path + 
                     " -out " + client_csr_path + 
                     " -subj \"" + subject + "\" 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Client CSR generated: " << client_csr_path << std::endl;
    return true;
}

bool CertificateManager::signClientCertificate(int validity_days) {
    std::cout << "\n=== Signing Client Certificate ===" << std::endl;
    
    if (!fileExists(root_key_path) || !fileExists(root_cert_path)) {
        std::cerr << "Root CA does not exist. Generate root CA first." << std::endl;
        return false;
    }
    
    if (!fileExists(client_csr_path)) {
        std::cerr << "Client CSR does not exist. Generate CSR first." << std::endl;
        return false;
    }
    
    std::string cmd = "openssl x509 -req -in " + client_csr_path + 
                     " -CA " + root_cert_path + 
                     " -CAkey " + root_key_path + 
                     " -CAcreateserial -out " + client_cert_path + 
                     " -days " + std::to_string(validity_days) + 
                     " -sha256 2>/dev/null";
    if (!executeCommand(cmd)) {
        return false;
    }
    
    std::cout << "Client certificate signed and generated: " << client_cert_path << std::endl;
    return true;
}

bool CertificateManager::generateAllCertificates() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Certificate Generation Process Started" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Setup directory
    if (!setupCertificateDirectory()) {
        std::cerr << "Failed to setup certificate directory" << std::endl;
        return false;
    }
    
    // Generate Root CA
    if (!generateRootCA()) {
        std::cerr << "Failed to generate Root CA" << std::endl;
        return false;
    }
    
    // Generate Server certificates
    if (!generateServerKey()) {
        std::cerr << "Failed to generate server key" << std::endl;
        return false;
    }
    
    if (!generateServerCSR()) {
        std::cerr << "Failed to generate server CSR" << std::endl;
        return false;
    }
    
    if (!signServerCertificate()) {
        std::cerr << "Failed to sign server certificate" << std::endl;
        return false;
    }
    
    // Generate Client certificates
    if (!generateClientKey()) {
        std::cerr << "Failed to generate client key" << std::endl;
        return false;
    }
    
    if (!generateClientCSR()) {
        std::cerr << "Failed to generate client CSR" << std::endl;
        return false;
    }
    
    if (!signClientCertificate()) {
        std::cerr << "Failed to sign client certificate" << std::endl;
        return false;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "All Certificates Generated Successfully" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "\nGenerated files in " << cert_dir << ":" << std::endl;
    std::cout << "  Root CA:" << std::endl;
    std::cout << "    - " << root_key_path << std::endl;
    std::cout << "    - " << root_cert_path << std::endl;
    std::cout << "  Server:" << std::endl;
    std::cout << "    - " << server_key_path << std::endl;
    std::cout << "    - " << server_csr_path << std::endl;
    std::cout << "    - " << server_cert_path << std::endl;
    std::cout << "  Client:" << std::endl;
    std::cout << "    - " << client_key_path << std::endl;
    std::cout << "    - " << client_csr_path << std::endl;
    std::cout << "    - " << client_cert_path << std::endl;
    std::cout << "========================================" << std::endl;
    
    return true;
}

bool CertificateManager::certificatesExist() {
    return fileExists(root_cert_path) && 
           fileExists(server_key_path) && 
           fileExists(server_cert_path) &&
           fileExists(client_key_path) && 
           fileExists(client_cert_path);
}
