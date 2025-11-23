#include "blink.h"
#include <iostream>
#include <fstream>
#include <unistd.h>

// ============================================================================
// GPIO Class Implementation
// ============================================================================

GPIO::GPIO(int gpio_pin) : pin(gpio_pin) {
    gpio_path = "/sys/class/gpio/gpio" + std::to_string(pin);
}

bool GPIO::writeToFile(const std::string& path, const std::string& value) {
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open " << path << std::endl;
        return false;
    }
    file << value;
    file.close();
    return true;
}

bool GPIO::exportGPIO() {
    // Check if already exported
    std::string check_path = "/sys/class/gpio/gpio" + std::to_string(pin);
    std::ifstream check(check_path);
    if (check.good()) {
        return true; // Already exported
    }
    
    return writeToFile("/sys/class/gpio/export", std::to_string(pin));
}

bool GPIO::unexportGPIO() {
    return writeToFile("/sys/class/gpio/unexport", std::to_string(pin));
}

bool GPIO::setup() {
    std::cout << "Setting up GPIO..." << std::endl;
    
    if (!exportGPIO()) {
        std::cerr << "Failed to export GPIO " << pin << std::endl;
        return false;
    }
    
    // Small delay to ensure export completes
    usleep(100000);
    
    // Set direction to output
    if (!writeToFile(gpio_path + "/direction", "out")) {
        std::cerr << "Failed to set GPIO direction" << std::endl;
        return false;
    }
    
    std::cout << "GPIO " << pin << " set as OUTPUT." << std::endl;
    return true;
}

bool GPIO::setValue(bool value) {
    return writeToFile(gpio_path + "/value", value ? "1" : "0");
}

void GPIO::cleanup() {
    std::cout << "Cleaning up GPIO..." << std::endl;
    setValue(false); // Turn off LED
    unexportGPIO();
    std::cout << "GPIO cleanup complete." << std::endl;
}
