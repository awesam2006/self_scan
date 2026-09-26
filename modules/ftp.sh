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
echo "[*] Starting FTP enumeration..."

OUTPUT=$(nmap -Pn -n -p "$PORT" \
    --script ftp-anon,ftp-syst \
    "$TARGET" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "[-] FTP enumeration failed"
    exit 1
fi

echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Anonymous FTP login allowed"; then

    echo "[!] Anonymous FTP detected"
    echo "Evidence: Anonymous FTP login allowed on port $PORT"

    write_finding \
        "Anonymous FTP Access" \
        "Anonymous FTP login allowed on port $PORT" \
        "Medium" \
        "Disable anonymous FTP access unless it is explicitly required and restrict anonymous permissions."

else

    echo "[+] Anonymous FTP not detected"

fi
