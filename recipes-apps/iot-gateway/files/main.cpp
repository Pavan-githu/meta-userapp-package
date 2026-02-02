#include "main.h"
#include "version.h"
#include "certificate.h"
#include "wifi_manager.h"
#include "blockchain.h"
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <csignal>
#include <cstdlib>
#include <unistd.h>

// Global variables for cleanup
GPIO* led_gpio = nullptr;
HttpsServer* server = nullptr;
std::atomic<bool> running(true);
std::atomic<bool> pause_led(false);  // Control LED blinking during user input
std::atomic<int> led_blink_speed(5);  // LED blink interval in seconds (default: 5)

// Global certificate paths
std::string global_cert_file;
std::string global_key_file;
std::atomic<bool> certificates_ready(false);

// Global WiFi IP address
std::string global_wifi_ip = "";
pthread_mutex_t ip_mutex = PTHREAD_MUTEX_INITIALIZER;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "\nShutting down..." << std::endl;
    running = false;
    
    if (server) {
        server->stop();
    }
    
    if (led_gpio) {
        led_gpio->cleanup();
    }
    
    exit(0);
}

// Thread function for LED blinking
void* ledBlinkThread(void* arg) {
    GPIO led(LED_PIN);
    led_gpio = &led;
    
    if (!led.setup()) {
        std::cerr << "Failed to setup GPIO. Make sure you have proper permissions." << std::endl;
        pthread_exit(NULL);
    }
    
    std::cout << "[LED Thread] Started on GPIO " << LED_PIN << std::endl;
    
    while (running) {
        // Check if LED should be paused (during user input)
        if (!pause_led) {
            int speed = led_blink_speed.load();  // Get current speed
            
            led.setValue(true);
            std::cout << "[LED] ON (speed: " << speed << "s)" << std::endl;
            sleep(speed);
            
            led.setValue(false);
            std::cout << "[LED] OFF" << std::endl;
            sleep(speed);
        } else {
            // Keep LED off during pause
            led.setValue(false);
            sleep(1);
        }
    }
    
    led.cleanup();
    std::cout << "[LED Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

// Thread function for WiFi management
void* wifiManagerThread(void* arg) {
    std::cout << "[WiFi Thread] Started" << std::endl;
    
    WiFiManager wifi_manager("wlan0");
    
    // Check if already connected
    if (wifi_manager.isConnected()) {
        std::cout << "[WiFi] Already connected to: " << wifi_manager.getCurrentSSID() << std::endl;
        std::string ip = wifi_manager.getIPAddress();
        std::cout << "[WiFi] IP Address: " << ip << std::endl;
        
        // Store IP globally
        pthread_mutex_lock(&ip_mutex);
        global_wifi_ip = ip;
        pthread_mutex_unlock(&ip_mutex);
    } else {
        std::cout << "[WiFi] Not connected to any network" << std::endl;
        
        // Try to auto-connect using saved configuration
        std::cout << "[WiFi] Checking for saved network configuration..." << std::endl;
        if (wifi_manager.autoConnect()) {
            std::cout << "[WiFi] Successfully auto-connected to saved network" << std::endl;
            std::string ip = wifi_manager.getIPAddress();
            std::cout << "[WiFi] IP Address: " << ip << std::endl;
            
            // Store IP globally
            pthread_mutex_lock(&ip_mutex);
            global_wifi_ip = ip;
            pthread_mutex_unlock(&ip_mutex);
        } else {
            // No saved config or auto-connect failed, prompt user
            std::cout << "[WiFi] No saved network or auto-connect failed" << std::endl;
            
            // Pause LED during user input
            pause_led = true;
            sleep(1); // Give LED thread time to turn off
            
            std::cout << "[WiFi] Do you want to setup WiFi? (y/n): ";
            char choice;
            std::cin >> choice;
            
            if (choice == 'y' || choice == 'Y') {
                if (wifi_manager.interactiveSetup()) {
                    // Store IP globally after successful connection
                    std::string ip = wifi_manager.getIPAddress();
                    pthread_mutex_lock(&ip_mutex);
                    global_wifi_ip = ip;
                    pthread_mutex_unlock(&ip_mutex);
                } else {
                    std::cerr << "[WiFi] Setup failed. Continuing without network..." << std::endl;
                }
            } else {
                std::cout << "[WiFi] Skipping setup. Server will be accessible only via Ethernet." << std::endl;
            }
            
            // Resume LED blinking
            pause_led = false;
        }
        
        // Resume LED blinking
        pause_led = false;
    }
    
    // Keep thread alive to monitor connection
    while (running) {
        sleep(30); // Check connection every 30 seconds
        if (!wifi_manager.isConnected()) {
            std::cout << "[WiFi] Connection lost" << std::endl;
        }
    }
    
    std::cout << "[WiFi Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

// Thread function for certificate management
void* certificateManagementThread(void* arg) {
    std::cout << "[Certificate Thread] Started" << std::endl;
    
    // Certificate management
    std::string cert_directory = "/etc/https-server";
    CertificateManager cert_manager(cert_directory);
    
    // Create certificate directory if it doesn't exist
    if (!cert_manager.setupCertificateDirectory()) {
        std::cerr << "[Certificate] Failed to create certificate directory: " << cert_directory << std::endl;
        std::cerr << "[Certificate] Make sure you have proper permissions (try running with sudo)." << std::endl;
        certificates_ready = false;
        pthread_exit(NULL);
    }
    
    // Check if certificates exist, if not generate them
    if (!cert_manager.certificatesExist()) {
        std::cout << "[Certificate] Certificates not found. Generating new certificates..." << std::endl;
        if (!cert_manager.generateAllCertificates()) {
            std::cerr << "[Certificate] Failed to generate certificates" << std::endl;
            std::cerr << "[Certificate] Make sure you have proper permissions and openssl is installed." << std::endl;
            certificates_ready = false;
            pthread_exit(NULL);
        }
        std::cout << "[Certificate] Certificates generated successfully!" << std::endl;
    } else {
        std::cout << "[Certificate] Certificates found in " << cert_directory << std::endl;
    }
    
    // Get certificate paths and store globally
    global_cert_file = cert_manager.getServerCertPath();
    global_key_file = cert_manager.getServerKeyPath();
    
    std::cout << "[Certificate] Server cert: " << global_cert_file << std::endl;
    std::cout << "[Certificate] Server key: " << global_key_file << std::endl;
    std::cout << "[Certificate] Root CA: " << cert_manager.getRootCertPath() << std::endl;
    std::cout << "[Certificate] Client cert: " << cert_manager.getClientCertPath() << std::endl;
    std::cout << "[Certificate] Client key: " << cert_manager.getClientKeyPath() << std::endl;
    
    // Signal that certificates are ready
    certificates_ready = true;
    
    std::cout << "[Certificate Thread] Completed successfully" << std::endl;
    pthread_exit(NULL);
}

// Thread function for HTTPS server
void* httpsServerThread(void* arg) {
    std::cout << "[HTTPS Thread] Started" << std::endl;
    
    // Wait for certificates to be ready
    std::cout << "[HTTPS] Waiting for certificates..." << std::endl;
    while (!certificates_ready && running) {
        sleep(1);
    }
    
    if (!certificates_ready) {
        std::cerr << "[HTTPS] Certificates not available, cannot start server" << std::endl;
        pthread_exit(NULL);
    }
    
    std::cout << "[HTTPS] Certificates ready, starting server..." << std::endl;
    
    // Use global certificate paths
    std::string cert_file = global_cert_file;
    std::string key_file = global_key_file;
    
    HttpsServer https_server(8443);
    server = &https_server;
    
    if (!https_server.start(cert_file.c_str(), key_file.c_str())) {
        std::cerr << "[HTTPS] Failed to start server" << std::endl;
        running = false;
        pthread_exit(NULL);
    }
    
    // Get WiFi IP address
    pthread_mutex_lock(&ip_mutex);
    std::string wifi_ip = global_wifi_ip;
    pthread_mutex_unlock(&ip_mutex);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "   HTTPS SERVER STARTED" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[HTTPS] Server running on port 8443" << std::endl;
    
    if (!wifi_ip.empty() && wifi_ip != "No IP assigned") {
        std::cout << "[HTTPS] WiFi URL: https://" << wifi_ip << ":8443/upload" << std::endl;
    }
    std::cout << "[HTTPS] Local URL: https://localhost:8443/upload" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Keep server running
    while (running) {
        sleep(1);
    }
    
    https_server.stop();
    std::cout << "[HTTPS Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

// Thread function for blockchain operations
void* blockchainOperationsThread(void* arg) {
    std::cout << "[Blockchain Thread] Started" << std::endl;

    // Example: Fetch firmware details
    std::string firmware_version_to_check = "1.4.2";
    std::cout << "[Blockchain] Fetching details for firmware version: " << firmware_version_to_check << std::endl;

    FirmwareDetails details = getFirmwareDetails(firmware_version_to_check);

    if (!details.version.empty()) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "   FIRMWARE DETAILS (from Blockchain)" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "  Version: " << details.version << std::endl;
        std::cout << "  Device Class: " << details.deviceClass << std::endl;
        std::cout << "  SHA256: " << details.sha256 << std::endl;
        std::cout << "  Artifact: " << details.artifact << std::endl;
        std::cout << "  Signed By: " << details.signedBy << std::endl;
        std::cout << "  Released At: " << details.releasedAt << std::endl;
        std::cout << "========================================\n" << std::endl;
    } else {
        std::cerr << "[Blockchain] Firmware version " << firmware_version_to_check << " not found." << std::endl;
    }

    std::cout << "[Blockchain Thread] Completed" << std::endl;
    pthread_exit(NULL);
}

int main(int argc, char** argv) {
    std::cout << "==================================================" << std::endl;
    std::cout << "  IoT Gateway Application " << VERSION_FULL_STRING << std::endl;
    std::cout << "  Version: " << VERSION_STRING << std::endl;
    std::cout << "  Build: " << BUILD_DATE << " " << BUILD_TIME << std::endl;
    std::cout << "  Git Commit: " << GIT_COMMIT << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "  - WiFi Setup (Thread)" << std::endl;
    std::cout << "  - LED Blink Controller (Thread)" << std::endl;
    std::cout << "  - HTTPS Firmware Upload Server (Thread)" << std::endl;
    std::cout << "  - Blockchain Operations (Thread)" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Launch all service threads using pthread
    std::cout << "\n--- Starting Service Threads (pthread) ---" << std::endl;
    
    pthread_t led_thread, cert_thread, wifi_thread, https_thread, blockchain_thread;
    
    // Create LED blink thread (independent of other services)
    if (pthread_create(&led_thread, NULL, ledBlinkThread, NULL) != 0) {
        std::cerr << "Failed to create LED thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] LED thread created" << std::endl;
    
    // Create certificate management thread
    if (pthread_create(&cert_thread, NULL, certificateManagementThread, NULL) != 0) {
        std::cerr << "Failed to create certificate thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] Certificate management thread created" << std::endl;
    
    // Create WiFi manager thread
    if (pthread_create(&wifi_thread, NULL, wifiManagerThread, NULL) != 0) {
        std::cerr << "Failed to create WiFi thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] WiFi thread created" << std::endl;
    
    // Create HTTPS server thread (will wait for certificates internally)
    if (pthread_create(&https_thread, NULL, httpsServerThread, NULL) != 0) {
        std::cerr << "Failed to create HTTPS thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] HTTPS thread created" << std::endl;

    // Create blockchain operations thread
    if (pthread_create(&blockchain_thread, NULL, blockchainOperationsThread, NULL) != 0) {
        std::cerr << "Failed to create blockchain thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] Blockchain thread created" << std::endl;
    
    std::cout << "\n==================================================" << std::endl;
    std::cout << "  All services running in separate threads!" << std::endl;
    std::cout << "  - LED: Blinking on GPIO " << LED_PIN << std::endl;
    std::cout << "  - Certificate: Management in progress" << std::endl;
    std::cout << "  - WiFi: Manager running" << std::endl;
    std::cout << "  - HTTPS: Server on port 8443 (waiting for certificates)" << std::endl;
    std::cout << "  - Blockchain: Fetching firmware details" << std::endl;
    std::cout << "    * Upload: https://localhost:8443/upload" << std::endl;
    std::cout << "  Press Ctrl+C to stop all services" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Wait for all threads to complete
    pthread_join(led_thread, NULL);
    pthread_join(cert_thread, NULL);
    pthread_join(wifi_thread, NULL);
    pthread_join(https_thread, NULL);
    pthread_join(blockchain_thread, NULL);
    
    std::cout << "\n=== IoT Gateway Application Stopped ===" << std::endl;
    return 0;
}
