# SelfScan

A Bash-based automated security assessment tool for authorized lab environments.

SelfScan performs reconnaissance, TCP port and service enumeration, service-specific security checks, and structured report generation.

## Project Overview

SelfScan was developed as a modular Bash security assessment tool.

The scanner follows this workflow:

```text
Target(s)
   ↓
4.1 Reconnaissance
   ↓
4.2 Port & Service Enumeration
   ↓
4.3 Automated Enumeration
   ↓
4.4 Security Checks
   ↓
4.5 Report Generation
```

The project is designed for authorized testing environments such as vulnerable virtual machines and isolated laboratory networks.

## Features

* Single-target scanning
* Multiple-target scanning from the command line
* Multiple-target scanning from a target list file
* Target reachability detection
* IPv4 target validation
* Target IP and hostname identification
* Basic network information
* Fast TCP port discovery using RustScan
* Service and version detection using Nmap
* Structured open-port extraction
* Open-port counting
* Automated service-specific enumeration
* Evidence-based security findings
* Risk classification and explanations
* Recommendations for detected findings
* Text-based security reports
* HTML security report generation
* Separate reports for multiple targets
* Error handling for invalid and unreachable targets
* Modular service enumeration architecture
* `--help` and `--version` support
* Execution logging
* Scan timing for RustScan, Nmap, automated enumeration, and total assessment

## Requirements

SelfScan requires:

* Bash
* RustScan
* Nmap

Optional system utilities used when available:

* `ping`
* `getent`
* `ip`

## Installation

Clone or copy the project into a Linux environment.

Make the main script executable:

```bash
chmod +x self_scan.sh
```

Make the service modules executable:

```bash
chmod +x modules/*.sh
```

Verify the required dependencies:

```bash
rustscan --version
nmap --version
```

## Usage

### Scan a single target

```bash
./self_scan.sh <target>
```

Example:

```bash
./self_scan.sh 192.168.34.129
```

### Scan multiple targets from the terminal

```bash
./self_scan.sh <target1> <target2> <target3>
```

Example:

```bash
./self_scan.sh 192.168.34.129 192.168.34.130 192.168.34.131
```

### Scan multiple targets from a file

```bash
./self_scan.sh targets.txt
```

The target file contains one IP address or hostname per line.

Example:

```text
192.168.34.129
192.168.34.130
192.168.34.131
```

Empty lines and lines beginning with `#` are ignored.

### Display help

```bash
./self_scan.sh --help
```

### Display the version

```bash
./self_scan.sh --version
```

## Project Structure

```text
self_scan/
├── self_scan.sh
├── modules/
│   ├── ftp.sh
│   ├── ssh.sh
│   ├── smb.sh
│   ├── smtp.sh
│   ├── dns.sh
│   └── http.sh
├── targets.example.txt
├── README.md
└── .gitignore
```

Generated reports and logs are stored in the `reports/` directory and are excluded from version control.

For a single-target scan:

```text
reports/
├── scan.txt
├── findings.txt
├── summary.txt
├── report.html
└── selfscan.log
```

For multiple-target scans, each target receives its own report directory:

```text
reports/
├── 192.168.34.129/
│   ├── scan.txt
│   ├── findings.txt
│   ├── summary.txt
│   ├── report.html
│   └── selfscan.log
├── 192.168.34.130/
│   ├── scan.txt
│   ├── findings.txt
│   ├── summary.txt
│   ├── report.html
│   └── selfscan.log
└── ...
```


## 4.1 Reconnaissance

The reconnaissance stage identifies basic information about the target.

It performs:

* Host availability checking
* Target IP validation
* IP address identification
* Hostname resolution when available
* Basic network information collection

Example information:

```text
Target IP
Target Hostname
Interface
Source IP
Gateway
```

## 4.2 Port & Service Enumeration

SelfScan uses a two-stage TCP enumeration process.

### Stage 1 — RustScan

RustScan is used for fast TCP port discovery.

### Stage 2 — Nmap

Nmap performs service and version detection against the discovered ports.

This approach avoids unnecessarily running detailed service detection against every TCP port.

Example detected information:

```text
21/tcp    ftp       vsftpd 2.3.4
22/tcp    ssh       OpenSSH 4.7p1
80/tcp    http      Apache httpd 2.2.8
139/tcp   netbios   Samba
```
SelfScan also records the execution time for each major scanning stage:

* RustScan duration
* Nmap service/version detection duration
* Automated enumeration duration
* Total assessment duration

## 4.3 Automated Enumeration

SelfScan detects services from the Nmap results and automatically selects the corresponding enumeration module.

### FTP

Checks:

* Anonymous FTP access
* FTP system information

### SSH

Checks:

* SSH banner
* SSH cryptographic algorithms
* Weak or obsolete algorithms

### SMB

Checks:

* SMB share enumeration
* Anonymous share access
* SMB protocol versions
* SMB message-signing configuration
* Basic SMB operating-system information

### SMTP

Checks:

* Open relay behavior
* SMTP user enumeration
* SMTP commands
* VRFY command exposure

### DNS

Checks:

* DNS version information
* DNS recursion
* DNS zone transfer capability when the required zone information is available

### HTTP

Checks:

* HTTP title
* HTTP headers
* Supported HTTP methods
* `robots.txt`
* Common web enumeration results
* Directory listing indicators
* Potential information-disclosure files

## 4.4 Security Checks

Security checks are based on evidence collected by the service modules.

Each detected finding contains:

```text
Finding
Port
Risk
Risk Explanation
Evidence
Recommendation
```

The scanner avoids reporting an issue as confirmed when the enumeration result is inconclusive.

For example:

```text
Open relay: inconclusive
SMTP user enumeration: inconclusive
```

rather than incorrectly reporting a confirmed vulnerability.

### Risk Classification

SelfScan uses a qualitative risk classification:

* **High** — potentially significant unauthorized access, data exposure, or service compromise
* **Medium** — increases attack surface or may assist further compromise
* **Low** — primarily exposes information or weakens a security control

The risk level is assigned based on the observed security condition; it is not a numerical CVSS calculation.

## 4.5 Report Generation

After the assessment is completed, SelfScan generates structured reports for the scanned target.

### `scan.txt`

Contains the complete scan overview:

* Target information
* Scan date
* Network information
* Open TCP ports
* Detected services
* Findings
* Timing information

### `findings.txt`

Contains detailed security findings including:

* Finding name
* Target
* Port
* Risk
* Risk explanation
* Evidence
* Recommendation

### `summary.txt`

Contains a condensed assessment summary including:

* Target information
* Open ports
* Detected services
* Total findings
* Findings grouped by risk
* Evidence and recommendations
* Timing information

### `report.html`

Contains a browser-viewable HTML version of the generated assessment information, including:

* Scan summary
* Security findings
* Detailed scan information
* Timing information

### `selfscan.log`

Contains the execution log for the scan, including scanner output, module execution, errors, status messages, and timing information.

## Error Handling

SelfScan handles common execution problems such as:

* Missing target
* Invalid target input
* Unreachable target
* Missing required dependencies
* Module execution failures

The scanner reports the error clearly and exits instead of continuing with invalid assessment data.

## Example

Example authorized lab target:

```text
Metasploitable 2
VMware virtual machine
Host-only Adapter network
```

Example single-target command:

```bash
./self_scan.sh 192.168.34.129
```

Example multiple-target command:

```bash
./self_scan.sh 192.168.34.129 192.168.34.130 192.168.34.131
```

Example target-list command:

```bash
./self_scan.sh targets.txt
```

Example generated reports for a single target:

```text
reports/scan.txt
reports/findings.txt
reports/summary.txt
reports/report.html
reports/selfscan.log
```

Example generated reports for multiple targets:

```text
reports/
├── 192.168.34.129/
│   ├── scan.txt
│   ├── findings.txt
│   ├── summary.txt
│   └── report.html
└── 192.168.34.130/
    ├── scan.txt
    ├── findings.txt
    ├── summary.txt
    └── report.html
```

## Security and Authorization

SelfScan is intended for authorized security assessment and educational laboratory environments.

Only scan systems that you own or have explicit permission to test.

## Project Goal

The goal of SelfScan is to demonstrate practical Bash scripting, automation, network reconnaissance, service enumeration, security checks, decision logic, file handling, error handling, report generation, execution logging, performance measurement, and modular software design.
