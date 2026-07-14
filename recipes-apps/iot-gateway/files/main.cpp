#include "main.h"
#include "certificate.h"
#include "wifi_manager.h"
#include "user_auth.h"
#include "blockchain_logger.h"
#include "firmwareupdate.h"
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Global variables for cleanup
GPIO* led_gpio = nullptr;
HttpsServer* server = nullptr;
FirmwareUpdateManager* fw_manager = nullptr;
std::atomic<bool> running(true);
std::atomic<bool> pause_led(false);  // Control LED blinking during user input
std::atomic<int> led_blink_speed(5);  // LED blink interval in seconds (default: 5)

// Global certificate paths
std::string global_cert_file;
std::string global_key_file;
std::atomic<bool> certificates_ready(false);

// Global WiFi IP address
std::string global_wifi_ip = "";
pthread_mutex_t ip_mutex = PTHREAD_MUTEX_INITIALIZER;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "\nShutting down..." << std::endl;
    running = false;
    
    if (server) {
        server->stop();
    }

    if (fw_manager) {
        fw_manager->cancel();
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
        // Check if LED should be paused (during user input)
        if (!pause_led) {
            int speed = led_blink_speed.load();  // Get current speed
            
            led.setValue(true);
            std::cout << "[LED] ON (speed: " << speed << "s)" << std::endl;
            sleep(speed);
            
            led.setValue(false);
            std::cout << "[LED] OFF" << std::endl;
            sleep(speed);
        } else {
            // Keep LED off during pause
            led.setValue(false);
            sleep(1);
        }
    }
    
    led.cleanup();
    std::cout << "[LED Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

// Thread function for startup audio playback.
// Plays an MP3 file at boot using mpg123 (fire-and-forget, detached).
void* audioStartupThread(void* arg) {
    const char* mp3_file = "/usr/share/iot-gateway/startup.mp3";
    std::string cmd = std::string("mpg123 -o alsa -q ") + mp3_file;
    int ret = system(cmd.c_str());
    if (ret != 0)
        std::cerr << "[Audio] mpg123 exited with code " << ret
                  << " — check mpg123 is installed and " << mp3_file << " exists" << std::endl;
    else
        std::cout << "[Audio] Startup audio playback complete" << std::endl;
    pthread_exit(NULL);
}

// Thread function for startup buzzer alert on GPIO 18 (BCM) via Linux sysfs.
// Fires once at boot to indicate the gateway is initialising.
void* buzzerStartupThread(void* arg) {
    // Export GPIO 18
    if (FILE* fp = fopen("/sys/class/gpio/export", "w")) {
        fputs("18", fp);
        fclose(fp);
    }
    // Allow kernel time to create the gpio18 sysfs entry
    usleep(100000);
    // Set pin direction to output
    if (FILE* fp = fopen("/sys/class/gpio/gpio18/direction", "w")) {
        fputs("out", fp);
        fclose(fp);
    }
    // 3 short startup pulses: 0.2 s HIGH + 0.2 s LOW
    for (int i = 0; i < 3; ++i) {
        if (FILE* fp = fopen("/sys/class/gpio/gpio18/value", "w")) {
            fputs("1", fp);
            fclose(fp);
        }
        usleep(200000);
        if (FILE* fp = fopen("/sys/class/gpio/gpio18/value", "w")) {
            fputs("0", fp);
            fclose(fp);
        }
        usleep(200000);
    }
    // Unexport GPIO 18 to release the pin
    if (FILE* fp = fopen("/sys/class/gpio/unexport", "w")) {
        fputs("18", fp);
        fclose(fp);
    }
    std::cout << "[Buzzer] Startup alert complete" << std::endl;
    pthread_exit(NULL);
}

// Thread function for WiFi management
void* wifiManagerThread(void* arg) {
    std::cout << "[WiFi Thread] Started" << std::endl;
    
    WiFiManager wifi_manager("wlan0");
    
    // Check if already connected
    if (wifi_manager.isConnected()) {
        std::cout << "[WiFi] Already connected to: " << wifi_manager.getCurrentSSID() << std::endl;
        std::string ip = wifi_manager.getIPAddress();
        std::cout << "[WiFi] IP Address: " << ip << std::endl;
        
        // Store IP globally
        pthread_mutex_lock(&ip_mutex);
        global_wifi_ip = ip;
        pthread_mutex_unlock(&ip_mutex);
    } else {
        std::cout << "[WiFi] Not connected to any network" << std::endl;
        
        // Try to auto-connect using saved configuration
        std::cout << "[WiFi] Checking for saved network configuration..." << std::endl;
        if (wifi_manager.autoConnect()) {
            std::cout << "[WiFi] Successfully auto-connected to saved network" << std::endl;
            std::string ip = wifi_manager.getIPAddress();
            std::cout << "[WiFi] IP Address: " << ip << std::endl;
            
            // Store IP globally
            pthread_mutex_lock(&ip_mutex);
            global_wifi_ip = ip;
            pthread_mutex_unlock(&ip_mutex);
        } else {
            // No saved config or auto-connect failed, prompt user
            std::cout << "[WiFi] No saved network or auto-connect failed" << std::endl;
            
            // Pause LED during user input
            pause_led = true;
            sleep(1); // Give LED thread time to turn off
            
            std::cout << "[WiFi] Do you want to setup WiFi? (y/n): ";
            char choice;
            std::cin >> choice;
            
            if (choice == 'y' || choice == 'Y') {
                if (wifi_manager.interactiveSetup()) {
                    // Store IP globally after successful connection
                    std::string ip = wifi_manager.getIPAddress();
                    pthread_mutex_lock(&ip_mutex);
                    global_wifi_ip = ip;
                    pthread_mutex_unlock(&ip_mutex);
                } else {
                    std::cerr << "[WiFi] Setup failed. Continuing without network..." << std::endl;
                }
            } else {
                std::cout << "[WiFi] Skipping setup. Server will be accessible only via Ethernet." << std::endl;
            }
            
            // Resume LED blinking
            pause_led = false;
        }
        
        // Resume LED blinking
        pause_led = false;
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

// Thread function for certificate management
void* certificateManagementThread(void* arg) {
    std::cout << "[Certificate Thread] Started" << std::endl;

    // ── Wait for system clock to be NTP-synchronized ─────────────────────────
    // The Pi 3 has no hardware RTC. On first boot the clock starts from the
    // fake-hwclock saved timestamp (often years in the past). Certificate
    // validity dates are embedded at generation time, so generating before
    // NTP sync produces certs with wrong notBefore/notAfter values.
    // We poll timedatectl until "synchronized: yes" or until 60 s elapses.
    {
        bool synced = false;
        for (int i = 0; i < 60 && !synced; ++i) {
            FILE* fp = popen("timedatectl show --property=NTPSynchronized --value 2>/dev/null", "r");
            if (fp) {
                char buf[16] = {};
                if (fgets(buf, sizeof(buf), fp))
                    synced = (std::string(buf).find("yes") != std::string::npos);
                pclose(fp);
            }
            if (!synced) {
                if (i == 0)
                    std::cout << "[Certificate] Waiting for NTP clock sync before generating certs..." << std::endl;
                sleep(1);
            }
        }
        if (synced)
            std::cout << "[Certificate] NTP synchronized — system clock is correct." << std::endl;
        else
            std::cerr << "[Certificate] WARNING: NTP sync timeout — certs may carry wrong date." << std::endl;
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Certificate management
    std::string cert_directory = "/etc/https-server";
    CertificateManager cert_manager(cert_directory);
    
    // Create certificate directory if it doesn't exist
    if (!cert_manager.setupCertificateDirectory()) {
        std::cerr << "[Certificate] Failed to create certificate directory: " << cert_directory << std::endl;
        std::cerr << "[Certificate] Make sure you have proper permissions (try running with sudo)." << std::endl;
        certificates_ready = false;
        pthread_exit(NULL);
    }
    
    // Check if certificates exist, if not generate them
    if (!cert_manager.certificatesExist()) {
        std::cout << "[Certificate] Certificates not found. Generating new certificates..." << std::endl;
        if (!cert_manager.generateAllCertificates()) {
            std::cerr << "[Certificate] Failed to generate certificates" << std::endl;
            std::cerr << "[Certificate] Make sure you have proper permissions and openssl is installed." << std::endl;
            certificates_ready = false;
            pthread_exit(NULL);
        }
        std::cout << "[Certificate] Certificates generated successfully!" << std::endl;
    } else {
        std::cout << "[Certificate] Certificates found in " << cert_directory << std::endl;
    }
    
    // Get certificate paths and store globally
    global_cert_file = cert_manager.getServerCertPath();
    global_key_file = cert_manager.getServerKeyPath();
    
    std::cout << "[Certificate] Server cert: " << global_cert_file << std::endl;
    std::cout << "[Certificate] Server key: " << global_key_file << std::endl;
    std::cout << "[Certificate] Root CA: " << cert_manager.getRootCertPath() << std::endl;
    std::cout << "[Certificate] Client cert: " << cert_manager.getClientCertPath() << std::endl;
    std::cout << "[Certificate] Client key: " << cert_manager.getClientKeyPath() << std::endl;
    
    // ── Certificate Validation ─────────────────────────────────────────────
    // After generation (or loading existing certs), validate all certificates:
    //   1. Server cert is signed by Root CA
    //   2. Client cert is signed by Root CA
    //   3. Server cert private key matches the certificate public key
    //   4. No certificate in the chain is expired
    //   5. Server cert SAN contains at least one DNS entry
    {
        bool validation_ok = true;

        // Load Root CA
        FILE* ca_fp = fopen(cert_manager.getRootCertPath().c_str(), "r");
        X509* ca_cert = ca_fp ? PEM_read_X509(ca_fp, nullptr, nullptr, nullptr) : nullptr;
        if (ca_fp) fclose(ca_fp);

        if (!ca_cert) {
            std::cerr << "[CertValidate] FAIL: Cannot load Root CA: "
                      << cert_manager.getRootCertPath() << std::endl;
            validation_ok = false;
        }

        // Build trusted store from Root CA
        X509_STORE* store = X509_STORE_new();
        if (store && ca_cert)
            X509_STORE_add_cert(store, ca_cert);

        // ── Validate server certificate ───────────────────────────────────
        FILE* srv_fp = fopen(cert_manager.getServerCertPath().c_str(), "r");
        X509* srv_cert = srv_fp ? PEM_read_X509(srv_fp, nullptr, nullptr, nullptr) : nullptr;
        if (srv_fp) fclose(srv_fp);

        if (!srv_cert) {
            std::cerr << "[CertValidate] FAIL: Cannot load server cert: "
                      << cert_manager.getServerCertPath() << std::endl;
            validation_ok = false;
        } else if (store) {
            X509_STORE_CTX* ctx = X509_STORE_CTX_new();
            X509_STORE_CTX_init(ctx, store, srv_cert, nullptr);
            if (X509_verify_cert(ctx) == 1) {
                std::cout << "[CertValidate] Server cert: chain OK — signed by Root CA" << std::endl;
            } else {
                std::cerr << "[CertValidate] FAIL: Server cert chain invalid: "
                          << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)) << std::endl;
                validation_ok = false;
            }
            X509_STORE_CTX_free(ctx);

            // Check server cert expiry
            int day = 0, sec = 0;
            ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(srv_cert));
            if (day < 0 || sec < 0) {
                std::cerr << "[CertValidate] FAIL: Server cert is EXPIRED" << std::endl;
                validation_ok = false;
            } else {
                std::cout << "[CertValidate] Server cert: valid for " << day << " more days" << std::endl;
            }

            // Check server cert SAN contains at least one DNS entry
            GENERAL_NAMES* san = (GENERAL_NAMES*)X509_get_ext_d2i(
                srv_cert, NID_subject_alt_name, nullptr, nullptr);
            int dns_count = 0;
            if (san) {
                for (int i = 0; i < sk_GENERAL_NAME_num(san); ++i) {
                    GENERAL_NAME* gn = sk_GENERAL_NAME_value(san, i);
                    if (gn->type == GEN_DNS) ++dns_count;
                }
                GENERAL_NAMES_free(san);
            }
            if (dns_count > 0)
                std::cout << "[CertValidate] Server cert: SAN has " << dns_count << " DNS entry/entries — OK" << std::endl;
            else {
                std::cerr << "[CertValidate] FAIL: Server cert SAN has no DNS entries — hostname validation will fail" << std::endl;
                validation_ok = false;
            }

            // Verify server private key matches server cert public key
            FILE* key_fp = fopen(cert_manager.getServerKeyPath().c_str(), "r");
            EVP_PKEY* srv_key = key_fp ? PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr) : nullptr;
            if (key_fp) fclose(key_fp);
            if (srv_key) {
                if (X509_check_private_key(srv_cert, srv_key) == 1)
                    std::cout << "[CertValidate] Server cert: private key matches certificate — OK" << std::endl;
                else {
                    std::cerr << "[CertValidate] FAIL: Server private key does NOT match certificate public key" << std::endl;
                    validation_ok = false;
                }
                EVP_PKEY_free(srv_key);
            } else {
                std::cerr << "[CertValidate] FAIL: Cannot load server private key" << std::endl;
                validation_ok = false;
            }
        }

        // ── Validate client certificate ───────────────────────────────────
        FILE* cli_fp = fopen(cert_manager.getClientCertPath().c_str(), "r");
        X509* cli_cert = cli_fp ? PEM_read_X509(cli_fp, nullptr, nullptr, nullptr) : nullptr;
        if (cli_fp) fclose(cli_fp);

        if (!cli_cert) {
            std::cerr << "[CertValidate] FAIL: Cannot load client cert: "
                      << cert_manager.getClientCertPath() << std::endl;
            validation_ok = false;
        } else if (store) {
            X509_STORE_CTX* ctx = X509_STORE_CTX_new();
            X509_STORE_CTX_init(ctx, store, cli_cert, nullptr);
            if (X509_verify_cert(ctx) == 1) {
                std::cout << "[CertValidate] Client cert: chain OK — signed by Root CA" << std::endl;
            } else {
                std::cerr << "[CertValidate] FAIL: Client cert chain invalid: "
                          << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)) << std::endl;
                validation_ok = false;
            }
            X509_STORE_CTX_free(ctx);

            // Check client cert expiry
            int day = 0, sec = 0;
            ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(cli_cert));
            if (day < 0 || sec < 0) {
                std::cerr << "[CertValidate] FAIL: Client cert is EXPIRED" << std::endl;
                validation_ok = false;
            } else {
                std::cout << "[CertValidate] Client cert: valid for " << day << " more days" << std::endl;
            }
        }

        // ── Root CA self-signature check ──────────────────────────────────
        if (ca_cert) {
            EVP_PKEY* ca_pub = X509_get_pubkey(ca_cert);
            if (ca_pub) {
                if (X509_verify(ca_cert, ca_pub) == 1)
                    std::cout << "[CertValidate] Root CA: self-signature valid — OK" << std::endl;
                else {
                    std::cerr << "[CertValidate] FAIL: Root CA self-signature invalid" << std::endl;
                    validation_ok = false;
                }
                EVP_PKEY_free(ca_pub);
            }
            // Check Root CA expiry
            int day = 0, sec = 0;
            ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(ca_cert));
            if (day < 0)
                std::cerr << "[CertValidate] FAIL: Root CA is EXPIRED" << std::endl;
            else
                std::cout << "[CertValidate] Root CA: valid for " << day << " more days" << std::endl;
        }

        // Cleanup
        if (srv_cert) X509_free(srv_cert);
        if (cli_cert) X509_free(cli_cert);
        if (ca_cert)  X509_free(ca_cert);
        if (store)    X509_STORE_free(store);

        if (!validation_ok) {
            std::cerr << "[CertValidate] One or more certificate checks FAILED — HTTPS server will not start" << std::endl;
            certificates_ready = false;
            pthread_exit(NULL);
        }
        std::cout << "[CertValidate] All certificate checks PASSED" << std::endl;
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Signal that certificates are ready
    certificates_ready = true;

    std::cout << "[Certificate Thread] Completed successfully" << std::endl;
    pthread_exit(NULL);
}

// Thread function for firmware OTA update management
//
// Reads /etc/iot-gateway/firmware.conf on startup and then polls every
// CHECK_INTERVAL_S seconds.  If the conf file specifies a newer version
// the update is downloaded, verified, and applied atomically.
//
// firmware.conf format (one key=value per line, # comments allowed):
//   FIRMWARE_URL=https://example.com/iot-gateway-1.2.3.bin
//   FIRMWARE_VERSION=1.2.3
//   FIRMWARE_SHA256=<64-char hex digest>
//   FIRMWARE_CA_CERT=/etc/ssl/certs/ca-certificates.crt
//   FIRMWARE_TARGET=/usr/bin/iot-gateway
//   FIRMWARE_STAGING=/tmp/iot-gateway.staging
//   FIRMWARE_BACKUP=/usr/bin/iot-gateway.bak
//   FIRMWARE_CHECK_INTERVAL=3600
void* firmwareUpdateThread(void* arg) {
    std::cout << "[FirmwareUpdate Thread] Started" << std::endl;

    // Read current version from /etc/iot-gateway-version (written by do_install)
    std::string current_version = "0.0.0";
    {
        std::ifstream vf("/etc/iot-gateway-version");
        if (vf.is_open()) std::getline(vf, current_version);
        while (!current_version.empty() &&
               (current_version.back() == '\n' || current_version.back() == '\r' ||
                current_version.back() == ' '))
            current_version.pop_back();
    }

    FirmwareUpdateManager mgr("/usr/bin/iot-gateway", current_version);
    fw_manager = &mgr;

    unsigned int check_interval = 3600; // default: check once per hour

    while (running) {
        // Re-read config on every cycle (allows runtime reconfiguration)
        FirmwareUpdateConfig cfg;
        cfg.ca_cert_path = "/etc/ssl/certs/ca-certificates.crt";
        cfg.target_path  = "/usr/bin/iot-gateway";
        cfg.staging_path = "/tmp/iot-gateway.staging";
        cfg.backup_path  = "/usr/bin/iot-gateway.bak";

        std::ifstream conf("/etc/iot-gateway/firmware.conf");
        if (conf.is_open()) {
            std::string line;
            while (std::getline(conf, line)) {
                if (line.empty() || line[0] == '#') continue;
                auto eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string key = line.substr(0, eq);
                std::string val = line.substr(eq + 1);
                while (!val.empty() &&
                       (val.back() == ' ' || val.back() == '\r' || val.back() == '\t'))
                    val.pop_back();
                if      (key == "FIRMWARE_URL")             cfg.url             = val;
                else if (key == "FIRMWARE_VERSION")         cfg.version         = val;
                else if (key == "FIRMWARE_SHA256")          cfg.expected_sha256 = val;
                else if (key == "FIRMWARE_CA_CERT")         cfg.ca_cert_path    = val;
                else if (key == "FIRMWARE_TARGET")          cfg.target_path     = val;
                else if (key == "FIRMWARE_STAGING")         cfg.staging_path    = val;
                else if (key == "FIRMWARE_BACKUP")          cfg.backup_path     = val;
                else if (key == "FIRMWARE_CHECK_INTERVAL")  check_interval      = static_cast<unsigned int>(std::stoul(val));
            }
        } else {
            std::cout << "[FirmwareUpdate] /etc/iot-gateway/firmware.conf not found — "
                         "OTA updates disabled" << std::endl;
            // Sleep and check again in case conf appears later
            for (unsigned int i = 0; i < check_interval && running; ++i) sleep(1);
            continue;
        }

        // Attempt update only when all required fields are present
        if (!cfg.url.empty() && !cfg.version.empty() && !cfg.expected_sha256.empty()) {
            FirmwareUpdateStatus cur = mgr.getStatus();
            if (cur == FirmwareUpdateStatus::IDLE ||
                cur == FirmwareUpdateStatus::SUCCESS ||
                cur == FirmwareUpdateStatus::FAILED) {
                std::cout << "[FirmwareUpdate] Checking for update: remote version "
                          << cfg.version << ", local version "
                          << mgr.getCurrentVersion() << std::endl;
                mgr.startUpdate(cfg); // no-op if already up-to-date or downgrade
            }
        }

        // Wait for the check interval, waking early if shutdown is requested
        for (unsigned int i = 0; i < check_interval && running; ++i) sleep(1);
    }

    fw_manager = nullptr;
    std::cout << "[FirmwareUpdate Thread] Stopped" << std::endl;
    pthread_exit(NULL);
}

// Thread function for HTTPS server
void* httpsServerThread(void* arg) {
    std::cout << "[HTTPS Thread] Started" << std::endl;
    
    // Wait for certificates to be ready
    std::cout << "[HTTPS] Waiting for certificates..." << std::endl;
    while (!certificates_ready && running) {
        sleep(1);
    }
    
    if (!certificates_ready) {
        std::cerr << "[HTTPS] Certificates not available, cannot start server" << std::endl;
        pthread_exit(NULL);
    }
    
    std::cout << "[HTTPS] Certificates ready, starting server..." << std::endl;
    
    // Use global certificate paths
    std::string cert_file = global_cert_file;
    std::string key_file = global_key_file;
    
    HttpsServer https_server(8443);
    server = &https_server;

    // ── MFA: initialise UserAuth and BlockchainLogger ────────────────────────
    // UserAuth: persistent PBKDF2 user registry with TOTP secrets
    UserAuth user_auth("/etc/iot-gateway/users.db");

    // BlockchainLogger: read config from /etc/iot-gateway/blockchain.conf
    // Format (one key=value per line):
    //   BLOCKCHAIN_RPC_URL=http://192.168.1.100:8545
    //   BLOCKCHAIN_CONTRACT=0x...
    //   BLOCKCHAIN_DEVICE_ADDR=0x...
    //   BLOCKCHAIN_CHAIN_ID=1337
    std::string bc_rpc      = "http://127.0.0.1:8545";
    std::string bc_contract = "";
    std::string bc_device   = "";
    uint64_t    bc_chain    = 1337;

    std::ifstream bc_conf("/etc/iot-gateway/blockchain.conf");
    if (bc_conf.is_open()) {
        std::string line;
        while (std::getline(bc_conf, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            // Strip trailing whitespace/CR from value
            while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\t'))
                val.pop_back();
            if      (key == "BLOCKCHAIN_RPC_URL")             bc_rpc      = val;
            else if (key == "BLOCKCHAIN_AUTHLOG_CONTRACT")    bc_contract = val;
            else if (key == "BLOCKCHAIN_CONTRACT")            bc_contract = val; // legacy
            else if (key == "BLOCKCHAIN_DEVICE_ADDR")         bc_device   = val;
            else if (key == "BLOCKCHAIN_CHAIN_ID")            bc_chain    = std::stoull(val);
        }
    } else {
        std::cerr << "[HTTPS] /etc/iot-gateway/blockchain.conf not found – "
                     "blockchain logging disabled\n";
    }

    BlockchainLogger* blockchain = nullptr;
    if (!bc_contract.empty() && !bc_device.empty()) {
        blockchain = new BlockchainLogger(bc_rpc, bc_contract, bc_device, bc_chain);
    } else {
        std::cerr << "[HTTPS] Blockchain not configured – OTP events won't be logged on-chain\n";
    }

    HttpsServer::initMFA(&user_auth, blockchain);
    // ────────────────────────────────────────────────────────────────────────
    
    // Pass the Root CA so the HTTPS server enforces mTLS: only connections
    // presenting a client certificate signed by this CA (i.e. cloudflared)
    // are accepted.  Any direct browser hit on port 8443 is rejected at the
    // TLS handshake before a single HTTP byte is processed.
    const char* trust_ca = "/etc/https-server/root-ca.crt";
    if (!https_server.start(cert_file.c_str(), key_file.c_str(), trust_ca)) {
        std::cerr << "[HTTPS] Failed to start server" << std::endl;
        running = false;
        pthread_exit(NULL);
    }
    
    // Get WiFi IP address
    pthread_mutex_lock(&ip_mutex);
    std::string wifi_ip = global_wifi_ip;
    pthread_mutex_unlock(&ip_mutex);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "   HTTPS SERVER STARTED" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[HTTPS] Server running on port 8443" << std::endl;
    
    if (!wifi_ip.empty() && wifi_ip != "No IP assigned") {
        std::cout << "[HTTPS] WiFi URL: https://" << wifi_ip << ":8443/upload" << std::endl;
    }
    std::cout << "[HTTPS] Local URL: https://localhost:8443/upload" << std::endl;

    // Show Cloudflare public URL if domain is configured
    std::string cf_domain;
    std::ifstream cf_conf("/etc/cloudflared/domain");
    if (cf_conf.is_open()) {
        std::getline(cf_conf, cf_domain);
        // Skip comment lines
        while (!cf_domain.empty() && cf_domain[0] == '#') {
            std::getline(cf_conf, cf_domain);
        }
        // Strip any accidental https:// prefix and trailing slash
        const std::string prefix = "https://";
        if (cf_domain.substr(0, prefix.size()) == prefix)
            cf_domain = cf_domain.substr(prefix.size());
        if (!cf_domain.empty() && cf_domain.back() == '/')
            cf_domain.pop_back();
    }
    if (!cf_domain.empty()) {
        std::cout << "[HTTPS] Public URL:  https://" << cf_domain << "/upload" << std::endl;
    }
    std::cout << "========================================\n" << std::endl;
    
    // Keep server running
    while (running) {
        sleep(1);
    }
    
    https_server.stop();
    delete blockchain;
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
    
    // Launch all service threads using pthread
    std::cout << "\n--- Starting Service Threads (pthread) ---" << std::endl;
    
    pthread_t led_thread, cert_thread, wifi_thread, https_thread, fw_thread;
    
    // Create LED blink thread (independent of other services)
    if (pthread_create(&led_thread, NULL, ledBlinkThread, NULL) != 0) {
        std::cerr << "Failed to create LED thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] LED thread created" << std::endl;

    // Create startup buzzer thread — fires once at boot, then exits naturally.
    // Runs detached so it does not need to be joined.
    {
        pthread_t buzz_thread;
        pthread_attr_t buzz_attr;
        pthread_attr_init(&buzz_attr);
        pthread_attr_setdetachstate(&buzz_attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&buzz_thread, &buzz_attr, buzzerStartupThread, NULL) != 0)
            std::cerr << "Failed to create startup buzzer thread" << std::endl;
        else
            std::cout << "[pthread] Startup buzzer thread created" << std::endl;
        pthread_attr_destroy(&buzz_attr);
    }
    // Create startup audio thread — plays startup.mp3 once at boot, then exits.
    // Runs detached so it does not need to be joined.
    {
        pthread_t audio_thread;
        pthread_attr_t audio_attr;
        pthread_attr_init(&audio_attr);
        pthread_attr_setdetachstate(&audio_attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&audio_thread, &audio_attr, audioStartupThread, NULL) != 0)
            std::cerr << "Failed to create startup audio thread" << std::endl;
        else
            std::cout << "[pthread] Startup audio thread created" << std::endl;
        pthread_attr_destroy(&audio_attr);
    }
    
    // Create certificate management thread
    if (pthread_create(&cert_thread, NULL, certificateManagementThread, NULL) != 0) {
        std::cerr << "Failed to create certificate thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] Certificate management thread created" << std::endl;
    
    // Create WiFi manager thread
    if (pthread_create(&wifi_thread, NULL, wifiManagerThread, NULL) != 0) {
        std::cerr << "Failed to create WiFi thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] WiFi thread created" << std::endl;
    
    // Create HTTPS server thread (will wait for certificates internally)
    if (pthread_create(&https_thread, NULL, httpsServerThread, NULL) != 0) {
        std::cerr << "Failed to create HTTPS thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] HTTPS thread created" << std::endl;

    // Create firmware OTA update thread
    if (pthread_create(&fw_thread, NULL, firmwareUpdateThread, NULL) != 0) {
        std::cerr << "Failed to create firmware update thread" << std::endl;
        return 1;
    }
    std::cout << "[pthread] Firmware update thread created" << std::endl;
    
    std::cout << "\n==================================================" << std::endl;
    std::cout << "  All services running in separate threads!" << std::endl;
    std::cout << "  - LED: Blinking on GPIO " << LED_PIN << std::endl;
    std::cout << "  - Certificate: Management in progress" << std::endl;
    std::cout << "  - WiFi: Manager running" << std::endl;
    std::cout << "  - HTTPS: Server on port 8443 (waiting for certificates)" << std::endl;
    std::cout << "    * Upload: https://localhost:8443/upload" << std::endl;
    std::cout << "  - Firmware OTA: Monitoring /etc/iot-gateway/firmware.conf" << std::endl;
    std::cout << "  Press Ctrl+C to stop all services" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Wait for all threads to complete
    pthread_join(led_thread, NULL);
    pthread_join(cert_thread, NULL);
    pthread_join(wifi_thread, NULL);
    pthread_join(https_thread, NULL);
    pthread_join(fw_thread, NULL);
    
    std::cout << "\n=== IoT Gateway Application Stopped ===" << std::endl;
    return 0;
}
