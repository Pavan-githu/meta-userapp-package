import RPi.GPIO as GPIO
import time

LED_PIN = 17

print("Setting up GPIO...")
GPIO.setmode(GPIO.BCM)
GPIO.setup(LED_PIN, GPIO.OUT)
print(f"GPIO {LED_PIN} set as OUTPUT.")

try:
    print("Starting LED blink loop. Press Ctrl+C to stop.")
    while True:
        GPIO.output(LED_PIN, GPIO.HIGH)
        print("LED ON")
        time.sleep(1)
        GPIO.output(LED_PIN, GPIO.LOW)
        print("LED OFF")
        time.sleep(1)
except KeyboardInterrupt:
    print("Interrupted by user. Cleaning up GPIO...")
    GPIO.cleanup()
    print("GPIO cleanup complete. Exiting.")