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

# Runs DNS enumeration and checks the results for security findings
run_dns_enum() {

    echo
    echo "[*] Starting DNS enumeration..."

    DNS_OUTPUT=$(nmap -Pn -n -p "$PORT" \
        --script dns-nsid,dns-recursion,dns-zone-transfer \
        "$TARGET" 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "[-] DNS enumeration failed"
        return 1
    fi

    echo "$DNS_OUTPUT"

    # ==========================================================
    # DNS version disclosure
    # ==========================================================

    DNS_VERSION=$(echo "$DNS_OUTPUT" |
        sed -n 's/.*bind.version: //p' |
        head -n 1)

    if [[ -n "$DNS_VERSION" ]]; then

        echo "[!] DNS version information disclosed: $DNS_VERSION"

        write_finding \
            "DNS Version Information Disclosure" \
            "DNS NSE reported bind.version: $DNS_VERSION" \
            "Low" \
            "Restrict unnecessary DNS version disclosure where possible."

    fi

    # ==========================================================
    # DNS recursion check
    # ==========================================================

    if echo "$DNS_OUTPUT" | grep -qiE \
        "Recursion appears to be enabled|recursive queries.*allowed"; then

        echo "[!] DNS recursion appears to be enabled"

        EVIDENCE=$(echo "$DNS_OUTPUT" |
            grep -iE "Recursion appears to be enabled|recursive queries.*allowed" |
            sed 's/^[[:space:]|]*//' |
            head -n 1)

        write_finding \
            "DNS Recursion Enabled" \
            "$EVIDENCE" \
            "Medium" \
            "Restrict recursive DNS queries to authorized clients and trusted networks."

    elif echo "$DNS_OUTPUT" | grep -qiE \
        "Recursion appears to be disabled|recursive queries.*not allowed"; then

        echo "[+] DNS recursion not detected"

    else

        echo "[!] DNS recursion result inconclusive"

    fi

    # ==========================================================
    # DNS zone transfer check
    # ==========================================================

    if echo "$DNS_OUTPUT" | grep -q "dns-zone-transfer:"; then

        echo "[!] DNS zone transfer information returned"

        write_finding \
            "DNS Zone Transfer Exposure" \
            "The dns-zone-transfer NSE script returned zone transfer information." \
            "High" \
            "Restrict DNS zone transfers to authorized secondary DNS servers only."

    elif echo "$DNS_OUTPUT" | grep -q "Skipping 'dns-zone-transfer'"; then

        echo "[!] DNS zone transfer could not be tested because the zone name was unavailable"

    else

        echo "[+] No DNS zone transfer information returned"

    fi
}

run_dns_enum
