#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include <string>
#include <vector>

// Structure to hold WiFi network information
struct WiFiNetwork {
    std::string ssid;
    int signal_strength;
    bool encrypted;
    std::string security_type;
    
    WiFiNetwork(const std::string& s, int strength, bool enc, const std::string& sec)
        : ssid(s), signal_strength(strength), encrypted(enc), security_type(sec) {}
};

// WiFi Manager class
class WiFiManager {
private:
    std::string interface_name;
    std::vector<WiFiNetwork> available_networks;
    
    // Helper methods
    bool executeCommand(const std::string& command, std::string& output);
    bool isWiFiEnabled();
    std::string getWiFiInterface();
    
public:
    // Constructor
    WiFiManager(const std::string& iface = "wlan0");
    
    // Initialize WiFi interface
    bool initialize();
    
    // Scan for available WiFi networks
    bool scanNetworks();
    
    // Get list of available networks
    std::vector<WiFiNetwork> getAvailableNetworks() const { return available_networks; }
    
    // Display available networks
    void displayNetworks() const;
    
    // Connect to a WiFi network
    bool connectToNetwork(const std::string& ssid, const std::string& password = "");
    
    // Check if connected to a network
    bool isConnected();
    
    // Get current connection info
    std::string getCurrentSSID();
    std::string getIPAddress();
    
    // Disconnect from current network
    bool disconnect();
    
    // Save network configuration to wpa_supplicant
    bool saveNetworkConfig(const std::string& ssid, const std::string& password);
    
    // Interactive WiFi setup (for user input)
    bool interactiveSetup();
};

#endif // WIFI_MANAGER_H
