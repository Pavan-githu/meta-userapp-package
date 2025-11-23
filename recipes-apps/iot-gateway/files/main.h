#ifndef MAIN_H
#define MAIN_H

#include "blink.h"
#include "https_server.h"
#include <atomic>

// LED GPIO pin definition
#define LED_PIN 17

// Global variables for cleanup
extern GPIO* led_gpio;
extern HttpsServer* server;
extern std::atomic<bool> running;

// Signal handler for graceful shutdown
void signalHandler(int signum);

// Thread function for LED blinking
void ledBlinkThread();

#endif // MAIN_H
