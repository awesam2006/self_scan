#!/bin/bash

# ==========================================================
# REQUIREMENT 4.3 - Automated Enumeration
# REQUIREMENT 4.4 - Security Checks
# BONUS #3 - Deep Service-Specific Enumeration
# BONUS #6 - Modular Architecture
# ==========================================================

TARGET="$1"
PORT="$2"
FINDINGS_FILE="${3:-reports/findings.txt}"

# Writes a structured security finding to the findings file
write_finding() {
    local title="$1"
    local evidence="$2"
    local risk="$3"
    local recommendation="$4"

    {
        echo "=========================================="
        echo "Finding: $title"
        echo "Target: $TARGET"
        echo "Port: $PORT"
        echo "Risk: $risk"
        echo "Evidence: $evidence"
        echo "Recommendation: $recommendation"
        echo
    } >> "$FINDINGS_FILE"
}

echo
echo "[*] Starting SSH enumeration..."

OUTPUT=$(nmap -Pn -n -p "$PORT" \
    --script banner,ssh2-enum-algos \
    "$TARGET" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "[-] SSH enumeration failed"
    exit 1
fi

echo "$OUTPUT"
echo "[+] SSH version/banner information collected"

# Checks for obsolete SSH cryptographic algorithms
WEAK_ALGORITHMS=$(echo "$OUTPUT" |
    grep -E 'diffie-hellman-group1-sha1|ssh-dss|arcfour|3des-cbc|blowfish-cbc|cast128-cbc|rijndael-cbc|hmac-md5' |
    sed 's/^[[:space:]]*//' |
    sed 's/^|[[:space:]]*//' |
    sort -u |
    paste -sd ',' - |
    sed 's/,/, /g')

if [[ -n "$WEAK_ALGORITHMS" ]]; then

    echo "[!] Weak SSH cryptographic algorithms detected"
    echo "Evidence: $WEAK_ALGORITHMS"

    write_finding \
        "Weak SSH Cryptographic Algorithms" \
        "SSH on port $PORT supports: $WEAK_ALGORITHMS" \
        "Medium" \
        "Disable obsolete key exchange, host key, cipher, and MAC algorithms and allow only modern cryptographic algorithms."

else

    echo "[+] No targeted weak SSH algorithms detected"

fi
