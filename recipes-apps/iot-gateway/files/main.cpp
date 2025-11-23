#include "main.h"
#include "certificate.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <csignal>
#include <cstdlib>

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
void ledBlinkThread() {
    GPIO led(LED_PIN);
    led_gpio = &led;
    
    if (!led.setup()) {
        std::cerr << "Failed to setup GPIO. Make sure you have proper permissions." << std::endl;
        return;
    }
    
    std::cout << "LED blink thread started on GPIO " << LED_PIN << std::endl;
    
    while (running) {
        led.setValue(true);
        std::cout << "LED ON" << std::endl;
        sleep(1);
        
        led.setValue(false);
        std::cout << "LED OFF" << std::endl;
        sleep(1);
    }
    
    led.cleanup();
}

int main(int argc, char** argv) {
    std::cout << "==================================================" << std::endl;
    std::cout << "  IoT Gateway Application" << std::endl;
    std::cout << "  - LED Blink Controller" << std::endl;
    std::cout << "  - HTTPS Firmware Upload Server" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Certificate management
    std::string cert_directory = "/etc/https-server";
    CertificateManager cert_manager(cert_directory);
    
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
    const char* cert_file = cert_manager.getServerCertPath().c_str();
    const char* key_file = cert_manager.getServerKeyPath().c_str();
    
    // Create HTTPS server instance
    HttpsServer https_server(8443);
    server = &https_server;
    
    // Start LED blink thread
    std::cout << "\nStarting LED blink thread..." << std::endl;
    std::thread led_thread(ledBlinkThread);
    
    // Start HTTPS server
    std::cout << "\nStarting HTTPS firmware server..." << std::endl;
    if (!https_server.start(cert_file, key_file)) {
        std::cerr << "Failed to start HTTPS server" << std::endl;
        running = false;
        led_thread.join();
        return 1;
    }
    
    std::cout << "\n==================================================" << std::endl;
    std::cout << "  Both services are running!" << std::endl;
    std::cout << "  - LED is blinking on GPIO " << LED_PIN << std::endl;
    std::cout << "  - HTTPS server: https://localhost:8443" << std::endl;
    std::cout << "  - Upload endpoint: https://localhost:8443/upload" << std::endl;
    std::cout << "  - Root CA: " << cert_manager.getRootCertPath() << std::endl;
    std::cout << "  - Client cert: " << cert_manager.getClientCertPath() << std::endl;
    std::cout << "  - Client key: " << cert_manager.getClientKeyPath() << std::endl;
    std::cout << "  Press Ctrl+C to stop" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Wait for LED thread to finish
    led_thread.join();
    
    return 0;
}
