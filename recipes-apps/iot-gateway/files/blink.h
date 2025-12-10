#ifndef BLINK_H
#define BLINK_H

#include <gpiod.h>

// GPIO control class using libgpiod (modern Linux GPIO API)
class GPIO {
private:
    int pin;
    struct gpiod_chip *chip;
    struct gpiod_line *line;
    
public:
    // Constructor
    GPIO(int gpio_pin);
    
    // Destructor
    ~GPIO();
    
    // Setup GPIO pin
    bool setup();
    
    // Set GPIO value (true = HIGH, false = LOW)
    bool setValue(bool value);
    
    // Cleanup GPIO
    void cleanup();
};

#endif // BLINK_H
