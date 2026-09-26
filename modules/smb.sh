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
echo "[*] Starting SMB enumeration..."

SMB_OUTPUT=$(nmap -Pn -n -p "$PORT" \
    --script smb-enum-shares,smb-protocols,smb-security-mode,smb-os-discovery \
    "$TARGET" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "[-] SMB enumeration failed"
    exit 1
fi

echo "$SMB_OUTPUT"

# ==========================================================
# Anonymous SMB access check
# ==========================================================

ANONYMOUS_SHARES=$(echo "$SMB_OUTPUT" |
    awk '
        /\\\\[^:]+:/ {
            share=$0
            sub(/^[[:space:]|]+/, "", share)
            sub(/:[[:space:]]*$/, "", share)
        }

        /Anonymous access: READ\/WRITE/ {
            if (share != "") {
                if (result == "")
                    result = share
                else
                    result = result ", " share  " — Anonymous READ/WRITE" 
		
            }
        }

        END {
            print result
        }
    ')

if [[ -n "$ANONYMOUS_SHARES" ]]; then

    echo "[!] Anonymous SMB READ/WRITE access detected"
    echo "Evidence: $ANONYMOUS_SHARES"

    write_finding \
        "Anonymous SMB READ/WRITE Access" \
        "The following SMB share(s) allow anonymous READ/WRITE access: $ANONYMOUS_SHARES" \
        "High" \
        "Disable anonymous SMB access and remove write permissions from unauthenticated users."

else

    echo "[+] Anonymous SMB READ/WRITE access not detected"

fi

# ==========================================================
# SMBv1 check
# ==========================================================

if echo "$SMB_OUTPUT" | grep -q "NT LM 0.12 (SMBv1)"; then

    echo "[!] SMBv1 detected"

    write_finding \
        "SMBv1 Enabled" \
        "Nmap smb-protocols reported: NT LM 0.12 (SMBv1)" \
        "High" \
        "Disable SMBv1 and require a modern SMB protocol version."

else

    echo "[+] SMBv1 not detected"

fi

# ==========================================================
# SMB message signing check
# ==========================================================

if echo "$SMB_OUTPUT" | grep -q "message_signing: disabled"; then

    echo "[!] SMB message signing is disabled"

    write_finding \
        "SMB Message Signing Disabled" \
        "Nmap smb-security-mode reported: message_signing: disabled" \
        "Medium" \
        "Enable SMB message signing to help protect SMB communications from tampering and relay-based attacks."

else

    echo "[+] SMB message signing not reported as disabled"

fi

# ==========================================================
# Enumeration status
# ==========================================================

if echo "$SMB_OUTPUT" | grep -q "smb-enum-shares:"; then
    echo "[+] SMB share enumeration completed"
else
    echo "[!] No SMB share information returned"
fi

if echo "$SMB_OUTPUT" | grep -q "smb-protocols:"; then
    echo "[+] SMB protocol enumeration completed"
fi

if echo "$SMB_OUTPUT" | grep -q "smb-security-mode:"; then
    echo "[+] SMB security mode enumeration completed"
fi

if echo "$SMB_OUTPUT" | grep -q "smb-os-discovery:"; then
    echo "[+] SMB OS discovery completed"
fi
