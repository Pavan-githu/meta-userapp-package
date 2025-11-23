#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <string>

// Certificate generation and management class
class CertificateManager {
private:
    std::string cert_dir;
    std::string root_key_path;
    std::string root_cert_path;
    std::string server_key_path;
    std::string server_csr_path;
    std::string server_cert_path;
    std::string client_key_path;
    std::string client_csr_path;
    std::string client_cert_path;
    
    // Helper methods
    bool executeCommand(const std::string& command);
    bool fileExists(const std::string& path);
    bool createDirectory(const std::string& path);
    
public:
    // Constructor
    CertificateManager(const std::string& certificate_directory = "/etc/https-server");
    
    // Setup certificate directory
    bool setupCertificateDirectory();
    
    // Generate Root CA
    bool generateRootCA(const std::string& subject = "/C=IN/ST=KA/L=Bengaluru/O=REVA/CN=RootCA");
    
    // Generate server key and CSR
    bool generateServerKey();
    bool generateServerCSR(const std::string& subject = "/C=IN/ST=KA/L=Bengaluru/O=REVA/CN=localhost");
    
    // Sign server certificate with root CA
    bool signServerCertificate(int validity_days = 3650);
    
    // Generate client key and CSR
    bool generateClientKey();
    bool generateClientCSR(const std::string& subject = "/C=IN/ST=KA/L=Bengaluru/O=REVA/CN=client");
    
    // Sign client certificate with root CA
    bool signClientCertificate(int validity_days = 3650);
    
    // Generate all certificates (root, server, client)
    bool generateAllCertificates();
    
    // Verify certificates exist
    bool certificatesExist();
    
    // Getters for certificate paths
    std::string getRootCertPath() const { return root_cert_path; }
    std::string getServerKeyPath() const { return server_key_path; }
    std::string getServerCertPath() const { return server_cert_path; }
    std::string getClientKeyPath() const { return client_key_path; }
    std::string getClientCertPath() const { return client_cert_path; }
    std::string getCertificateDirectory() const { return cert_dir; }
};

#endif // CERTIFICATE_H
