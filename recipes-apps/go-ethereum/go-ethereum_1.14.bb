SUMMARY = "go-ethereum geth — private dev-mode Ethereum node for RaceIoT"
DESCRIPTION = "Pre-built geth ARM binary. Runs in --dev mode on the RPi3 so \
the commit-reveal OTP contracts have a local blockchain without any VPS."
LICENSE = "LGPL-3.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/LGPL-3.0-only;md5=9f3523885f45e867ad7e73a622e5f6bd"

# Pre-built geth 1.14.x ARM32 (armv7l) binary from the official go-ethereum release.
# Check https://geth.ethereum.org/downloads for the latest ARM32 tarball and update
# SRC_URI + md5 checksum accordingly.
SRC_URI = "https://gethstore.blob.core.windows.net/builds/geth-linux-arm7-1.14.12-293a300d.tar.gz;name=geth-arm"
SRC_URI[geth-arm.md5sum]    = "REPLACE_WITH_REAL_MD5"
SRC_URI[geth-arm.sha256sum] = "REPLACE_WITH_REAL_SHA256"

# No build step — pre-built binary
do_compile[noexec] = "1"

S = "${WORKDIR}/geth-linux-arm7-1.14.12-293a300d"

do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${S}/geth ${D}${sbindir}/geth

    # Data directory that persists contract state across reboots
    install -d -m 0700 ${D}/var/lib/geth
}

# systemd service: starts geth --dev after wlan0 is up, before iot-gateway
do_install:append() {
    install -d ${D}${systemd_system_unitdir}
    cat > ${D}${systemd_system_unitdir}/geth-dev.service << 'EOF'
[Unit]
Description=geth private dev-mode Ethereum node
After=network-online.target
Wants=network-online.target
Before=iot-gateway.service

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/geth \
    --dev \
    --dev.period 2 \
    --http \
    --http.addr 127.0.0.1 \
    --http.port 8545 \
    --http.api eth,net,web3,personal,miner \
    --http.corsdomain "*" \
    --datadir /var/lib/geth \
    --verbosity 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # First-boot contract deployment script
    install -d ${D}${sbindir}
    cat > ${D}${sbindir}/deploy-contracts.sh << 'EOF'
#!/bin/sh
# deploy-contracts.sh
# Run once after first boot to deploy CommitRevealOTP and AuthLog contracts.
# Called by deploy-contracts.service (After=geth-dev.service).
#
# Uses raw JSON-RPC eth_sendTransaction — no Node.js required.
# Bytecode is embedded below (compiled offline with solc or hardhat).
# Replace BYTECODE_AUTHLOG and BYTECODE_COMMITREVEAL with real compiled output.

GETH_URL="http://127.0.0.1:8545"
STATE_FILE="/var/lib/geth/deployed.flag"

if [ -f "$STATE_FILE" ]; then
    echo "[deploy] Contracts already deployed — skipping."
    exit 0
fi

echo "[deploy] Waiting for geth to be ready..."
for i in $(seq 1 30); do
    BLOCK=$(curl -s -X POST "$GETH_URL" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$BLOCK" ]; then
        echo "[deploy] geth ready at block $BLOCK"
        break
    fi
    sleep 1
done

# Get the funded dev account
FROM=$(curl -s -X POST "$GETH_URL" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":2}' \
    | grep -o '"0x[^"]*"' | head -1 | tr -d '"')

echo "[deploy] Using account: $FROM"

# --- Deploy AuthLog ---
BYTECODE_AUTHLOG="0x__REPLACE_AUTHLOG_BYTECODE__"
TX1=$(curl -s -X POST "$GETH_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$FROM\",\"gas\":\"0x4C4B40\",\"data\":\"$BYTECODE_AUTHLOG\"}],\"id\":3}" \
    | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
echo "[deploy] AuthLog tx: $TX1"
sleep 3

# --- Deploy CommitRevealOTP ---
BYTECODE_COMMITREVEAL="0x__REPLACE_COMMITREVEAL_BYTECODE__"
TX2=$(curl -s -X POST "$GETH_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$FROM\",\"gas\":\"0x4C4B40\",\"data\":\"$BYTECODE_COMMITREVEAL\"}],\"id\":4}" \
    | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
echo "[deploy] CommitRevealOTP tx: $TX2"
sleep 3

# Write blockchain.conf
AUTHLOG_ADDR=$(curl -s -X POST "$GETH_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX1\"],\"id\":5}" \
    | grep -o '"contractAddress":"[^"]*"' | cut -d'"' -f4)

COMMITREVEAL_ADDR=$(curl -s -X POST "$GETH_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX2\"],\"id\":6}" \
    | grep -o '"contractAddress":"[^"]*"' | cut -d'"' -f4)

cat > /etc/iot-gateway/blockchain.conf << CONF
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_AUTHLOG_CONTRACT=$AUTHLOG_ADDR
BLOCKCHAIN_COMMITREVEAL_CONTRACT=$COMMITREVEAL_ADDR
BLOCKCHAIN_DEVICE_ADDR=$FROM
BLOCKCHAIN_CHAIN_ID=1337
CONF

echo "[deploy] blockchain.conf written:"
cat /etc/iot-gateway/blockchain.conf

touch "$STATE_FILE"
echo "[deploy] Done."
EOF
    chmod 0755 ${D}${sbindir}/deploy-contracts.sh

    # One-shot systemd unit that runs the deployment script after geth starts
    cat > ${D}${systemd_system_unitdir}/deploy-contracts.service << 'EOF'
[Unit]
Description=Deploy RaceIoT smart contracts to local geth node
After=geth-dev.service
Requires=geth-dev.service
ConditionPathExists=!/var/lib/geth/deployed.flag

[Service]
Type=oneshot
ExecStart=/usr/sbin/deploy-contracts.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

inherit systemd

SYSTEMD_SERVICE:${PN}  = "geth-dev.service deploy-contracts.service"
SYSTEMD_AUTO_ENABLE    = "enable"

FILES:${PN} += " \
    ${sbindir}/geth \
    ${sbindir}/deploy-contracts.sh \
    /var/lib/geth \
    ${systemd_system_unitdir}/geth-dev.service \
    ${systemd_system_unitdir}/deploy-contracts.service \
"
