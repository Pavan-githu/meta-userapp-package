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

// Signal handler for graceful shutdown
void signalHandler(int signum);

// Thread functions for pthread
void* ledBlinkThread(void* arg);
void* wifiManagerThread(void* arg);
void* httpsServerThread(void* arg);

#endif // MAIN_H
