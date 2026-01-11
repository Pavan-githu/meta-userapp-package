#ifndef MAIN_H
#define MAIN_H

#include "blink.h"
#include "https_server.h"
#include <atomic>
#include <pthread.h>

// LED GPIO pin definition
#define LED_PIN 17

// Structure to pass certificate paths to HTTPS thread
struct HttpsThreadArgs {
    std::string cert_file;
    std::string key_file;
};

// Global variables for cleanup
extern GPIO* led_gpio;
extern HttpsServer* server;
extern std::atomic<bool> running;
extern std::atomic<bool> pause_led;
extern std::atomic<int> led_blink_speed;

// Global certificate paths (set by certificate thread)
extern std::string global_cert_file;
extern std::string global_key_file;
extern std::atomic<bool> certificates_ready;

// Global WiFi IP address
extern std::string global_wifi_ip;
extern pthread_mutex_t ip_mutex;

// Signal handler for graceful shutdown
void signalHandler(int signum);

// Thread functions for pthread
void* ledBlinkThread(void* arg);
void* wifiManagerThread(void* arg);
void* httpsServerThread(void* arg);
void* certificateManagementThread(void* arg);

#endif // MAIN_H
