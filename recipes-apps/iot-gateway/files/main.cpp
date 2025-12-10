#include "main.h"
#include "certificate.h"
#include "wifi_manager.h"
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
        led.setValue(true);
        std::cout << "[LED] ON" << std::endl;
        sleep(5);
        
        led.setValue(false);
        std::cout << "[LED] OFF" << std::endl;
        sleep(5);
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
        std::cout << "[WiFi] IP Address: " << wifi_manager.getIPAddress() << std::endl;
    } else {
        std::cout << "[WiFi] Not connected to any network" << std::endl;
        std::cout << "[WiFi] Do you want to setup WiFi? (y/n): ";
        char choice;
        std::cin >> choice;
        
        if (choice == 'y' || choice == 'Y') {
            if (!wifi_manager.interactiveSetup()) {
                std::cerr << "[WiFi] Setup failed. Continuing without network..." << std::endl;
            }
        } else {
            std::cout << "[WiFi] Skipping setup. Server will be accessible only via Ethernet." << std::endl;
        }
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

// Thread function for HTTPS server
void* httpsServerThread(void* arg) {
    std::cout << "[HTTPS Thread] Started" << std::endl;
    
    // Extract certificate paths from argument
    HttpsThreadArgs* args = (HttpsThreadArgs*)arg;
    std::string cert_file = args->cert_file;
    std::string key_file = args->key_file;
    delete args; // Free the allocated memory
    
    HttpsServer https_server(8443);
    server = &https_server;
    
    if (!https_server.start(cert_file.c_str(), key_file.c_str())) {
        std::cerr << "[HTTPS] Failed to start server" << std::endl;
        running = false;
        pthread_exit(NULL);
    }
    
    std::cout << "[HTTPS] Server running on port 8443" << std::endl;
    
    // Keep server running
    while (running) {
        sleep(1);
    }
    
    https_server.stop();
    std::cout << "[HTTPS Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

int main(int argc, char** argv) {
    std::cout << "==================================================" << std::endl;
    std::cout << "  IoT Gateway Application" << std::endl;
    std::cout << "  - WiFi Setup (Thread)" << std::endl;
    std::cout << "  - LED Blink Controller (Thread)" << std::endl;
    std::cout << "  - HTTPS Firmware Upload Server (Thread)" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Launch LED thread first (independent of certificates)
    std::cout << "\n--- Starting LED Blink Thread (pthread) ---" << std::endl;
    
    pthread_t led_thread;
    
    // Create LED blink thread
    if (pthread_create(&led_thread, NULL, ledBlinkThread, NULL) != 0) {
        std::cerr << "Failed to create LED thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] LED thread created" << std::endl;
    
    // Certificate management
    std::string cert_directory = "/etc/https-server";
    CertificateManager cert_manager(cert_directory);
    
    // Create certificate directory if it doesn't exist
    if (!cert_manager.setupCertificateDirectory()) {
        std::cerr << "Failed to create certificate directory: " << cert_directory << std::endl;
        std::cerr << "Make sure you have proper permissions (try running with sudo)." << std::endl;
        return 1;
    }
    
    // Check if certificates exist, if not generate them
    if (!cert_manager.certificatesExist()) {
        std::cout << "\nCertificates not found. Generating new certificates..." << std::endl;
        if (!cert_manager.generateAllCertificates()) {
            std::cerr << "Failed to generate certificates" << std::endl;
            std::cerr << "Make sure you have proper permissions and openssl is installed." << std::endl;
            return 1;
        }
    } else {
        std::cout << "\nCertificates found in " << cert_directory << std::endl;
    }
    
    // Get certificate paths
    std::string cert_file = cert_manager.getServerCertPath();
    std::string key_file = cert_manager.getServerKeyPath();
    
    // Launch remaining service threads using pthread
    std::cout << "\n--- Starting Network Service Threads (pthread) ---" << std::endl;
    
    pthread_t wifi_thread, https_thread;
    
    // Create WiFi manager thread
    if (pthread_create(&wifi_thread, NULL, wifiManagerThread, NULL) != 0) {
        std::cerr << "Failed to create WiFi thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] WiFi thread created" << std::endl;
    
    // Create HTTPS server thread with certificate paths
    HttpsThreadArgs* https_args = new HttpsThreadArgs{cert_file, key_file};
    if (pthread_create(&https_thread, NULL, httpsServerThread, (void*)https_args) != 0) {
        std::cerr << "Failed to create HTTPS thread" << std::endl;
        delete https_args;
        return 1;
    }
    std::cout << "[pthread] HTTPS thread created" << std::endl;
    
    std::cout << "\n==================================================" << std::endl;
    std::cout << "  All services running in separate threads!" << std::endl;
    std::cout << "  - LED: Blinking on GPIO " << LED_PIN << std::endl;
    std::cout << "  - WiFi: Manager running" << std::endl;
    std::cout << "  - HTTPS: Server on port 8443" << std::endl;
    std::cout << "    * Upload: https://localhost:8443/upload" << std::endl;
    std::cout << "    * Root CA: " << cert_manager.getRootCertPath() << std::endl;
    std::cout << "    * Client cert: " << cert_manager.getClientCertPath() << std::endl;
    std::cout << "    * Client key: " << cert_manager.getClientKeyPath() << std::endl;
    std::cout << "  Press Ctrl+C to stop all services" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Wait for all threads to complete
    pthread_join(led_thread, NULL);
    pthread_join(wifi_thread, NULL);
    pthread_join(https_thread, NULL);
    
    std::cout << "\n=== IoT Gateway Application Stopped ===" << std::endl;
    return 0;
}
