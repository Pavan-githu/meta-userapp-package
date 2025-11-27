#include "wifi_manager.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

// ============================================================================
// WiFiManager Implementation
// ============================================================================

WiFiManager::WiFiManager(const std::string& iface) : interface_name(iface) {}

bool WiFiManager::executeCommand(const std::string& command, std::string& output) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to execute command: " << command << std::endl;
        return false;
    }
    
    char buffer[256];
    output.clear();
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int status = pclose(pipe);
    return (status == 0);
}

std::string WiFiManager::getWiFiInterface() {
    std::string output;
    executeCommand("ip link show | grep wlan | awk '{print $2}' | tr -d ':'", output);
    
    if (output.empty()) {
        return "wlan0"; // Default fallback
    }
    
    // Remove newline
    output.erase(output.find_last_not_of(" \n\r\t") + 1);
    return output;
}

bool WiFiManager::isWiFiEnabled() {
    std::string output;
    std::string cmd = "ip link show " + interface_name + " | grep 'state UP'";
    return executeCommand(cmd, output) && !output.empty();
}

bool WiFiManager::initialize() {
    std::cout << "Initializing WiFi Manager..." << std::endl;
    
    // Auto-detect WiFi interface if needed
    if (interface_name.empty() || interface_name == "wlan0") {
        interface_name = getWiFiInterface();
        std::cout << "Detected WiFi interface: " << interface_name << std::endl;
    }
    
    // Bring up the interface
    std::string output;
    std::string cmd = "ip link set " + interface_name + " up";
    if (!executeCommand(cmd, output)) {
        std::cerr << "Failed to bring up interface: " << interface_name << std::endl;
        return false;
    }
    
    sleep(2); // Wait for interface to come up
    
    std::cout << "WiFi interface " << interface_name << " initialized successfully" << std::endl;
    return true;
}

bool WiFiManager::scanNetworks() {
    std::cout << "\nScanning for WiFi networks..." << std::endl;
    available_networks.clear();
    
    // Trigger scan
    std::string output;
    std::string cmd = "iwlist " + interface_name + " scan";
    if (!executeCommand(cmd, output)) {
        std::cerr << "Failed to scan networks. Try running with sudo." << std::endl;
        return false;
    }
    
    // Parse scan results
    std::istringstream iss(output);
    std::string line;
    std::string current_ssid;
    int signal_strength = 0;
    bool encrypted = false;
    std::string security = "Open";
    
    while (std::getline(iss, line)) {
        // Parse SSID
        if (line.find("ESSID:") != std::string::npos) {
            size_t start = line.find("\"");
            size_t end = line.rfind("\"");
            if (start != std::string::npos && end != std::string::npos && end > start) {
                current_ssid = line.substr(start + 1, end - start - 1);
            }
        }
        // Parse signal quality
        else if (line.find("Quality=") != std::string::npos) {
            size_t pos = line.find("Quality=");
            if (pos != std::string::npos) {
                std::string quality_str = line.substr(pos + 8);
                size_t slash = quality_str.find("/");
                if (slash != std::string::npos) {
                    int current = std::stoi(quality_str.substr(0, slash));
                    int max = std::stoi(quality_str.substr(slash + 1));
                    signal_strength = (current * 100) / max;
                }
            }
        }
        // Parse encryption
        else if (line.find("Encryption key:on") != std::string::npos) {
            encrypted = true;
        }
        else if (line.find("IE: WPA") != std::string::npos) {
            security = "WPA/WPA2";
        }
        // End of a network entry
        else if (line.find("Cell ") != std::string::npos && !current_ssid.empty()) {
            available_networks.push_back(WiFiNetwork(current_ssid, signal_strength, encrypted, security));
            current_ssid.clear();
            signal_strength = 0;
            encrypted = false;
            security = "Open";
        }
    }
    
    // Add the last network
    if (!current_ssid.empty()) {
        available_networks.push_back(WiFiNetwork(current_ssid, signal_strength, encrypted, security));
    }
    
    std::cout << "Found " << available_networks.size() << " networks" << std::endl;
    return !available_networks.empty();
}

void WiFiManager::displayNetworks() const {
    if (available_networks.empty()) {
        std::cout << "No networks found. Run scanNetworks() first." << std::endl;
        return;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Available WiFi Networks:" << std::endl;
    std::cout << "========================================" << std::endl;
    
    for (size_t i = 0; i < available_networks.size(); i++) {
        const auto& net = available_networks[i];
        std::cout << "[" << (i + 1) << "] ";
        std::cout << net.ssid;
        std::cout << " (Signal: " << net.signal_strength << "%)";
        std::cout << " [" << (net.encrypted ? net.security_type : "Open") << "]";
        std::cout << std::endl;
    }
    std::cout << "========================================" << std::endl;
}

bool WiFiManager::saveNetworkConfig(const std::string& ssid, const std::string& password) {
    std::cout << "Saving network configuration..." << std::endl;
    
    // Create wpa_supplicant configuration
    std::string config;
    if (password.empty()) {
        // Open network
        config = "network={\n";
        config += "    ssid=\"" + ssid + "\"\n";
        config += "    key_mgmt=NONE\n";
        config += "}\n";
    } else {
        // WPA/WPA2 network
        config = "network={\n";
        config += "    ssid=\"" + ssid + "\"\n";
        config += "    psk=\"" + password + "\"\n";
        config += "}\n";
    }
    
    // Append to wpa_supplicant.conf
    std::ofstream conf_file("/etc/wpa_supplicant/wpa_supplicant.conf", std::ios::app);
    if (!conf_file.is_open()) {
        std::cerr << "Failed to open wpa_supplicant.conf. Try running with sudo." << std::endl;
        return false;
    }
    
    conf_file << config;
    conf_file.close();
    
    std::cout << "Configuration saved successfully" << std::endl;
    return true;
}

bool WiFiManager::connectToNetwork(const std::string& ssid, const std::string& password) {
    std::cout << "\nConnecting to: " << ssid << std::endl;
    
    // Save configuration
    if (!saveNetworkConfig(ssid, password)) {
        return false;
    }
    
    // Restart wpa_supplicant
    std::string output;
    std::cout << "Restarting wpa_supplicant..." << std::endl;
    
    // Kill existing wpa_supplicant
    executeCommand("killall wpa_supplicant 2>/dev/null", output);
    sleep(1);
    
    // Start wpa_supplicant
    std::string cmd = "wpa_supplicant -B -i " + interface_name + 
                     " -c /etc/wpa_supplicant/wpa_supplicant.conf";
    if (!executeCommand(cmd, output)) {
        std::cerr << "Failed to start wpa_supplicant" << std::endl;
        return false;
    }
    
    sleep(3); // Wait for connection
    
    // Get IP address via DHCP
    std::cout << "Requesting IP address..." << std::endl;
    cmd = "udhcpc -i " + interface_name;
    executeCommand(cmd, output);
    
    sleep(2);
    
    // Check if connected
    if (isConnected()) {
        std::cout << "\n✓ Successfully connected to " << ssid << std::endl;
        std::cout << "IP Address: " << getIPAddress() << std::endl;
        return true;
    } else {
        std::cerr << "✗ Failed to connect to " << ssid << std::endl;
        return false;
    }
}

bool WiFiManager::isConnected() {
    std::string output;
    std::string cmd = "iwconfig " + interface_name + " | grep 'ESSID' | grep -v 'off/any'";
    return executeCommand(cmd, output) && !output.empty();
}

std::string WiFiManager::getCurrentSSID() {
    std::string output;
    std::string cmd = "iwconfig " + interface_name + " | grep 'ESSID' | awk -F'\"' '{print $2}'";
    executeCommand(cmd, output);
    
    // Remove newline
    output.erase(output.find_last_not_of(" \n\r\t") + 1);
    return output;
}

std::string WiFiManager::getIPAddress() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return "Unable to get IP";
    }
    
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return "No IP assigned";
    }
    
    close(fd);
    
    return inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
}

bool WiFiManager::disconnect() {
    std::cout << "Disconnecting from WiFi..." << std::endl;
    
    std::string output;
    executeCommand("killall wpa_supplicant 2>/dev/null", output);
    
    std::string cmd = "ip addr flush dev " + interface_name;
    executeCommand(cmd, output);
    
    std::cout << "Disconnected" << std::endl;
    return true;
}

bool WiFiManager::interactiveSetup() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "   WiFi Interactive Setup" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Initialize
    if (!initialize()) {
        std::cerr << "Failed to initialize WiFi interface" << std::endl;
        return false;
    }
    
    // Scan networks
    if (!scanNetworks()) {
        std::cerr << "Failed to scan networks" << std::endl;
        return false;
    }
    
    // Display networks
    displayNetworks();
    
    // User selection
    std::cout << "\nEnter network number (1-" << available_networks.size() << ") or 0 to exit: ";
    int choice;
    std::cin >> choice;
    
    if (choice == 0) {
        std::cout << "Setup cancelled" << std::endl;
        return false;
    }
    
    if (choice < 1 || choice > static_cast<int>(available_networks.size())) {
        std::cerr << "Invalid selection" << std::endl;
        return false;
    }
    
    const WiFiNetwork& selected = available_networks[choice - 1];
    std::string password;
    
    if (selected.encrypted) {
        std::cout << "Enter password for " << selected.ssid << ": ";
        std::cin >> password;
    }
    
    // Connect
    return connectToNetwork(selected.ssid, password);
}
