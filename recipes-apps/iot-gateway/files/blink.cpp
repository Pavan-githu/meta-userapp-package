#include "blink.h"
#include <iostream>
#include <gpiod.h>

// ============================================================================
// GPIO Class Implementation using libgpiod (modern Linux GPIO API)
// ============================================================================

GPIO::GPIO(int gpio_pin) : pin(gpio_pin), chip(nullptr), line(nullptr) {
}

GPIO::~GPIO() {
    cleanup();
}

bool GPIO::setup() {
    std::cout << "Setting up GPIO with libgpiod..." << std::endl;
    
    // Open GPIO chip (gpiochip0 for Raspberry Pi)
    chip = gpiod_chip_open("/dev/gpiochip0");
    if (!chip) {
        std::cerr << "Failed to open GPIO chip" << std::endl;
        return false;
    }
    
    // Get GPIO line
    line = gpiod_chip_get_line(chip, pin);
    if (!line) {
        std::cerr << "Failed to get GPIO line " << pin << std::endl;
        gpiod_chip_close(chip);
        chip = nullptr;
        return false;
    }
    
    // Request line as output
    if (gpiod_line_request_output(line, "iot-gateway-led", 0) < 0) {
        std::cerr << "Failed to request GPIO " << pin << " as output" << std::endl;
        gpiod_chip_close(chip);
        chip = nullptr;
        line = nullptr;
        return false;
    }
    
    std::cout << "GPIO " << pin << " set as OUTPUT using libgpiod." << std::endl;
    return true;
}

bool GPIO::setValue(bool value) {
    if (!line) {
        std::cerr << "GPIO line not initialized" << std::endl;
        return false;
    }
    
    // Set GPIO value (1 = HIGH, 0 = LOW)
    if (gpiod_line_set_value(line, value ? 1 : 0) < 0) {
        std::cerr << "Failed to set GPIO " << pin << " value" << std::endl;
        return false;
    }
    
    return true;
}

void GPIO::cleanup() {
    std::cout << "Cleaning up GPIO..." << std::endl;
    
    if (line) {
        setValue(false); // Turn off LED
        gpiod_line_release(line);
        line = nullptr;
    }
    
    if (chip) {
        gpiod_chip_close(chip);
        chip = nullptr;
    }
    
    std::cout << "GPIO cleanup complete." << std::endl;
}
