#include "wifi_manager.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <limits>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <termios.h>
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

std::string WiFiManager::getPasswordHidden() {
    std::string password;
    struct termios oldt, newt;
    
    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    
    // Disable echo
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    // Read password
    std::getline(std::cin, password);
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    std::cout << std::endl; // Print newline after hidden input
    return password;
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
    std::string cmd = "iw " + interface_name + " scan";
    std::cout << "[CHECK] Executing scan command: " << cmd << std::endl;
    
    if (!executeCommand(cmd, output)) {
        std::cerr << "[ERROR] Failed to scan networks. Try running with sudo." << std::endl;
        return false;
    }
    
    std::cout << "[CHECK] Scan completed. Output size: " << output.size() << " bytes" << std::endl;
    
    // Parse scan results
    std::istringstream iss(output);
    std::string line;
    std::string current_ssid;
    int signal_strength = 0;
    bool encrypted = false;
    std::string security = "Open";
    
    while (std::getline(iss, line)) {
        // Check for start of a new BSS (network) entry - save previous one if exists
        if (line.find("BSS ") != std::string::npos && !current_ssid.empty()) {
            available_networks.push_back(WiFiNetwork(current_ssid, signal_strength, encrypted, security));
            current_ssid.clear();
            signal_strength = 0;
            encrypted = false;
            security = "Open";
        }
        // Parse SSID (iw format: "SSID: network_name")
        else if (line.find("SSID:") != std::string::npos) {
            size_t pos = line.find("SSID:");
            if (pos != std::string::npos) {
                current_ssid = line.substr(pos + 6);
                // Trim whitespace
                current_ssid.erase(0, current_ssid.find_first_not_of(" \t"));
                current_ssid.erase(current_ssid.find_last_not_of(" \t\r\n") + 1);
            }
        }
        // Parse signal strength (iw format: "signal: -XX.00 dBm")
        else if (line.find("signal:") != std::string::npos) {
            size_t pos = line.find("signal:");
            if (pos != std::string::npos) {
                std::string signal_str = line.substr(pos + 7);
                size_t dbm_pos = signal_str.find("dBm");
                if (dbm_pos != std::string::npos) {
                    try {
                        float signal_dbm = std::stof(signal_str.substr(0, dbm_pos));
                        // Convert dBm to percentage (approximate)
                        // -30 dBm = 100%, -90 dBm = 0%
                        signal_strength = std::max(0, std::min(100, (int)((signal_dbm + 90) * 100 / 60)));
                    } catch (...) {
                        signal_strength = 0;
                    }
                }
            }
        }
        // Parse encryption - iw shows RSN, WPA
        else if (line.find("RSN:") != std::string::npos || line.find("WPA:") != std::string::npos) {
            encrypted = true;
            security = "WPA/WPA2";
        }
    }
    
    // Add the last network
    if (!current_ssid.empty()) {
        available_networks.push_back(WiFiNetwork(current_ssid, signal_strength, encrypted, security));
    }
    
    std::cout << "[CHECK] Initial parse found " << available_networks.size() << " network entries" << std::endl;
    
    // Remove duplicates (networks appear multiple times in scan)
    std::vector<WiFiNetwork> unique_networks;
    for (const auto& net : available_networks) {
        bool found = false;
        for (const auto& unique : unique_networks) {
            if (unique.ssid == net.ssid) {
                found = true;
                break;
            }
        }
        if (!found && !net.ssid.empty()) {
            unique_networks.push_back(net);
            std::cout << "[CHECK] Added unique network: " << net.ssid 
                      << " (" << net.signal_strength << "%, " 
                      << (net.encrypted ? net.security_type : "Open") << ")" << std::endl;
        }
    }
    available_networks = unique_networks;
    
    std::cout << "[CHECK] Final count after deduplication: " << available_networks.size() << " networks" << std::endl;
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
    std::cout << "\n[CHECK] Saving network configuration..." << std::endl;
    std::cout << "[CHECK] SSID: " << ssid << std::endl;
    std::cout << "[CHECK] Password length: " << password.length() << " characters" << std::endl;
    
    const std::string conf_path = "/etc/wpa_supplicant.conf";
    std::cout << "[CHECK] Config file path: " << conf_path << std::endl;
    
    // Check if file exists, if not create with basic config
    std::ifstream check_file(conf_path);
    bool file_exists = check_file.good();
    check_file.close();
    
    if (!file_exists) {
        std::cout << "[CHECK] Config file doesn't exist, creating new one..." << std::endl;
        std::ofstream new_file(conf_path);
        if (!new_file.is_open()) {
            std::cerr << "[ERROR] Failed to create wpa_supplicant.conf. Try running with sudo." << std::endl;
            return false;
        }
        new_file << "ctrl_interface=/var/run/wpa_supplicant\n";
        new_file << "update_config=1\n\n";
        new_file.close();
        std::cout << "[CHECK] Config file created with headers" << std::endl;
    } else {
        std::cout << "[CHECK] Config file already exists" << std::endl;
    }
    
    // Create wpa_supplicant configuration using wpa_passphrase
    std::string config;
    if (password.empty()) {
        // Open network
        std::cout << "[CHECK] Configuring for open network (no password)" << std::endl;
        config = "network={\n";
        config += "    ssid=\"" + ssid + "\"\n";
        config += "    key_mgmt=NONE\n";
        config += "}\n";
    } else {
        // Use wpa_passphrase to generate proper PSK hash
        std::cout << "[CHECK] Generating PSK hash using wpa_passphrase..." << std::endl;
        std::string output;
        std::string cmd = "wpa_passphrase \"" + ssid + "\" \"" + password + "\" 2>&1";
        if (executeCommand(cmd, output)) {
            // wpa_passphrase generates the config, use it directly
            std::cout << "[CHECK] wpa_passphrase executed successfully" << std::endl;
            std::cout << "[CHECK] Generated config (first 100 chars): " 
                      << output.substr(0, std::min((size_t)100, output.size())) << "..." << std::endl;
            config = output;
        } else {
            // Fallback to manual config if wpa_passphrase fails
            std::cerr << "[WARNING] wpa_passphrase failed, using plaintext password" << std::endl;
            config = "network={\n";
            config += "    ssid=\"" + ssid + "\"\n";
            config += "    psk=\"" + password + "\"\n";
            config += "}\n";
        }
    }
    
    // Append to wpa_supplicant.conf
    std::cout << "[CHECK] Writing configuration to file..." << std::endl;
    std::ofstream conf_file(conf_path, std::ios::app);
    if (!conf_file.is_open()) {
        std::cerr << "[ERROR] Failed to open wpa_supplicant.conf. Try running with sudo." << std::endl;
        return false;
    }
    
    conf_file << config;
    conf_file.close();
    
    std::cout << "[CHECK] Configuration written successfully (" << config.size() << " bytes)" << std::endl;
    std::cout << "[CHECK] Network configuration saved to " << conf_path << std::endl;
    return true;
}

bool WiFiManager::connectToNetwork(const std::string& ssid, const std::string& password) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "[CHECK] Starting connection to: " << ssid << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Save configuration
    std::cout << "\n[STEP 1/4] Saving network configuration..." << std::endl;
    if (!saveNetworkConfig(ssid, password)) {
        std::cerr << "[ERROR] Failed to save network configuration" << std::endl;
        return false;
    }
    std::cout << "[STEP 1/4] ✓ Configuration saved" << std::endl;
    
    // Restart wpa_supplicant
    std::string output;
    std::cout << "\n[STEP 2/4] Restarting wpa_supplicant..." << std::endl;
    
    // Kill existing wpa_supplicant
    std::cout << "[CHECK] Killing existing wpa_supplicant processes..." << std::endl;
    executeCommand("killall wpa_supplicant 2>/dev/null", output);
    sleep(1);
    std::cout << "[CHECK] Old processes terminated" << std::endl;
    
    // Start wpa_supplicant
    std::string cmd = "wpa_supplicant -B -i " + interface_name + 
                     " -c /etc/wpa_supplicant.conf";
    std::cout << "[CHECK] Starting wpa_supplicant: " << cmd << std::endl;
    if (!executeCommand(cmd, output)) {
        std::cerr << "[ERROR] Failed to start wpa_supplicant" << std::endl;
        if (!output.empty()) {
            std::cerr << "[ERROR] Output: " << output << std::endl;
        }
        return false;
    }
    std::cout << "[STEP 2/4] ✓ wpa_supplicant started" << std::endl;
    
    // Wait for connection with timeout
    std::cout << "\n[STEP 3/4] Waiting for connection to " << ssid << std::endl;
    std::cout << "[CHECK] Monitoring connection status" << std::flush;
    int timeout = 15; // 15 seconds timeout
    bool connected = false;
    for (int i = 0; i < timeout; i++) {
        sleep(1);
        std::cout << "." << std::flush;
        if (isConnected()) {
            connected = true;
            std::cout << " Connected at " << (i + 1) << "s" << std::endl;
            break;
        }
    }
    if (!connected) {
        std::cout << " Timeout" << std::endl;
    }
    
    // Check if connected
    if (!connected) {
        std::cerr << "\n[ERROR] ✗ Failed to connect to " << ssid << std::endl;
        std::cerr << "[CHECK] Possible reasons:\n";
        std::cerr << "  - Incorrect password\n";
        std::cerr << "  - Signal too weak\n";
        std::cerr << "  - Network configuration issue\n";
        std::cerr << "\n[DEBUG] Check wpa_supplicant logs: tail -f /var/log/messages" << std::endl;
        std::cerr << "[DEBUG] Or run: wpa_cli -i " << interface_name << " status" << std::endl;
        return false;
    }
    
    std::cout << "[STEP 3/4] ✓ Connected to " << ssid << std::endl;
    
    // Get IP address via DHCP
    std::cout << "\n[STEP 4/4] Requesting IP address via DHCP..." << std::endl;
    cmd = "udhcpc -i " + interface_name + " 2>&1";
    std::cout << "[CHECK] Running: " << cmd << std::endl;
    executeCommand(cmd, output);
    
    sleep(2);
    
    std::string ip = getIPAddress();
    std::cout << "[CHECK] Obtained IP: " << ip << std::endl;
    std::cout << "[STEP 4/4] ✓ IP address assigned" << std::endl;
    
    // Final status
    std::cout << "\n========================================" << std::endl;
    std::cout << "   CONNECTION SUCCESSFUL" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "✓ Network: " << ssid << std::endl;
    std::cout << "✓ Interface: " << interface_name << std::endl;
    std::cout << "✓ IP Address: " << ip << std::endl;
    std::cout << "========================================\n" << std::endl;
    return true;
}

bool WiFiManager::isConnected() {
    std::string output;
    std::string cmd = "iw " + interface_name + " link | grep 'Connected'";
    return executeCommand(cmd, output) && !output.empty();
}

std::string WiFiManager::getCurrentSSID() {
    std::string output;
    std::string cmd = "iw " + interface_name + " link | grep 'SSID' | awk '{print $2}'";
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
    std::cout << "\n[CHECK] Selected network #" << choice << ": " << selected.ssid << std::endl;
    std::cout << "[CHECK] Signal strength: " << selected.signal_strength << "%" << std::endl;
    std::cout << "[CHECK] Security: " << (selected.encrypted ? selected.security_type : "Open") << std::endl;
    
    std::string password;
    
    if (selected.encrypted) {
        // Clear input buffer
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        std::cout << "\n[CHECK] Network is encrypted, password required" << std::endl;
        std::cout << "Enter password for " << selected.ssid << ": ";
        password = getPasswordHidden();  // Use hidden password input
        
        std::cout << "[CHECK] Password received (length: " << password.length() << " chars)" << std::endl;
        
        if (password.empty()) {
            std::cerr << "[ERROR] Password cannot be empty for encrypted network" << std::endl;
            return false;
        }
    } else {
        std::cout << "\n[CHECK] Open network, no password required" << std::endl;
    }
    
    // Connect
    return connectToNetwork(selected.ssid, password);
}
