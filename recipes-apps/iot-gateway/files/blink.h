#ifndef BLINK_H
#define BLINK_H

#include <string>

// GPIO control class for Raspberry Pi
class GPIO {
private:
    int pin;
    std::string gpio_path;
    
    // Private helper methods
    bool writeToFile(const std::string& path, const std::string& value);
    bool exportGPIO();
    bool unexportGPIO();
    
public:
    // Constructor
    GPIO(int gpio_pin);
    
    // Setup GPIO pin
    bool setup();
    
    // Set GPIO value (true = HIGH, false = LOW)
    bool setValue(bool value);
    
    // Cleanup GPIO
    void cleanup();
};

#endif // BLINK_H
