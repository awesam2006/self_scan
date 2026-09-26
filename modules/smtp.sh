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

# Runs SMTP command, open relay, and user enumeration checks
run_smtp_enum() {

    echo
    echo "[*] Starting SMTP enumeration..."

    SMTP_OUTPUT=$(nmap -Pn -n -p "$PORT" \
        --script smtp-open-relay,smtp-enum-users,smtp-commands \
        "$TARGET" 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "[-] SMTP enumeration failed"
        return 1
    fi

    echo "$SMTP_OUTPUT"

    # ==========================================================
    # Open relay check
    # ==========================================================

    if echo "$SMTP_OUTPUT" | grep -qiE \
        "Server is an open relay|open relay.*success|relay.*successful"; then

        echo "[!] SMTP open relay detected"

        EVIDENCE=$(echo "$SMTP_OUTPUT" |
            grep -iE "open relay|relay" |
            sed 's/^[[:space:]|]*//' |
            paste -sd ' ' -)

        write_finding \
            "SMTP Open Relay" \
            "$EVIDENCE" \
            "High" \
            "Restrict SMTP relay permissions to authorized users and trusted networks."

    elif echo "$SMTP_OUTPUT" | grep -qiE \
        "all tests failed|Failed to issue relaytest|connection timeout"; then

        echo "[!] Open relay: inconclusive"

    else

        echo "[+] Open relay: not detected"

    fi

    # ==========================================================
    # SMTP user enumeration
    # ==========================================================

    if echo "$SMTP_OUTPUT" | grep -qE \
        "unhandled status code|Failed to issue RCPT|Failed to issue VRFY|connection timeout"; then

        echo "[!] SMTP user enumeration: inconclusive"

    elif echo "$SMTP_OUTPUT" | grep -q "smtp-enum-users:"; then

        USER_RESULTS=$(echo "$SMTP_OUTPUT" |
            sed -n '/smtp-enum-users:/,/^[^|]/p' |
            sed 's/^[[:space:]|]*//' |
            grep -v '^smtp-enum-users:$' |
            paste -sd ' ' -)

        if [[ -n "$USER_RESULTS" ]]; then

            echo "[!] SMTP user enumeration information returned"
            echo "Evidence: $USER_RESULTS"

            write_finding \
                "SMTP User Enumeration" \
                "SMTP user enumeration returned: $USER_RESULTS" \
                "Medium" \
                "Restrict or disable SMTP commands that allow remote user enumeration where they are not required."

        else

            echo "[!] SMTP user enumeration: no users confirmed"

        fi

    else

        echo "[!] SMTP user enumeration: inconclusive"

    fi
    # ==========================================================
    # SMTP VRFY command exposure
    # ==========================================================

    if echo "$SMTP_OUTPUT" | grep -qE \
        "smtp-commands:.*VRFY|PIPELINING.*VRFY|VRFY,|, VRFY"; then

        echo "[!] SMTP VRFY command is enabled"

        write_finding \
            "SMTP VRFY Command Enabled" \
            "SMTP server advertised the VRFY command in its EHLO/command response." \
            "Low" \
            "Disable the VRFY command if it is not required to reduce the possibility of remote user enumeration."

    fi
    # ==========================================================
    # SMTP command enumeration
    # ==========================================================

    if echo "$SMTP_OUTPUT" | grep -q "smtp-commands:"; then
        echo "[+] SMTP command enumeration completed"
    else
        echo "[!] SMTP command enumeration: no result"
    fi
}

run_smtp_enum
