# 🛡️ Automated Email Threat & Phishing Investigation Platform

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success.svg)](https://yogs011.github.io/phishing-email-analyzer/)
[![SOC Focus](https://img.shields.io/badge/Blue%20Team-SOC%20Tier--1-green.svg)](#)

> **Live Deployed Web Application:** [https://yogs011.github.io/phishing-email-analyzer/](https://yogs011.github.io/phishing-email-analyzer/)  
> **Developed by:** [Yogesh Birla](https://github.com/yogs011)  
> **Role Alignment:** Security Operations Center (SOC) / Blue Team Incident Response  
> **Target Threat Vector:** Email-based Social Engineering (Phishing, BEC, Domain Spoofing)

---

## 📌 Overview

In modern Security Operations Centers (SOC), email remains the primary initial access vector ([MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)). Tier-1 SOC analysts frequently triage dozens of user-reported suspicious emails daily. Performing manual header inspection, decoding routing hops, defanging URLs, and computing attachment hashes is time-consuming and prone to human error.

This project is an end-to-end **Automated Email Threat & Phishing Investigation Platform** built in Python with both a **CLI engine**, an interactive **Streamlit Dashboard**, and a **Live Web Application**. It accelerates Tier-1 triage by parsing raw `.eml` artifacts, evaluating core authentication protocols (**SPF, DKIM, DMARC**), identifying domain spoofing, extracting and defanging Indicators of Compromise (IoCs), and generating actionable triage verdicts.

---

## 🌐 Live Web Application

The interactive web tool is deployed live and directly accessible in the browser:  
👉 **[Open Live SOC Phishing Analyzer](https://yogs011.github.io/phishing-email-analyzer/)**

---

## ⚡ Key Capabilities

* **RFC 5322 Header Forensics:**
  * Extracts standard fields (`From`, `To`, `Subject`, `Date`, `Message-ID`).
  * Traces server hops in the `Received` chain to reveal the true originating client/relay IP.
  * Detects discrepancies between `From`, `Return-Path`, and `Reply-To` (classic Business Email Compromise & spoofing indicator).

* **Authentication & Anti-Spoofing Verification:**
  * Automatically parses `Authentication-Results` and `Received-SPF`.
  * Validates **SPF** (Sender Policy Framework) to verify authorized sending IPs.
  * Checks **DKIM** (DomainKeys Identified Mail) cryptographic signature validity.
  * Assesses **DMARC** (Domain-based Message Authentication, Reporting & Conformance) alignment.

* **Automated IoC Extraction & Defanging:**
  * Recursively extracts embedded hyperlinks from plaintext and HTML bodies.
  * Defangs all extracted URLs (`http://` $\rightarrow$ `hxxp://`, `.` $\rightarrow$ `[.]`) to prevent accidental clicks during investigation.
  * Highlights direct IP-based links frequently used in credential-harvesting kits.

* **Cryptographic Attachment Fingerprinting:**
  * Extracts attachments and computes **MD5** and **SHA-256** hashes.
  * Flags high-risk executable and script extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.hta`, `.zip`).
  * Prepares hash summaries for threat intelligence enrichment (VirusTotal / Hybrid-Analysis).

* **Tier-1 Scoring Engine & Reporting:**
  * Calculates an objective Risk Score (0 to 100) based on weighted risk signals.
  * Classifies emails into **BENIGN / LOW RISK**, **SUSPICIOUS (Needs L2 Triage)**, or **MALICIOUS / HIGH RISK**.
  * Generates downloadable JSON triage reports for documentation in ticketing systems (Jira / ServiceNow / TheHive).

---

## 🏗️ System Workflow

```
       +-----------------------+
       |   Raw .eml Artifact   |
       +-----------+-----------+
                   |
                   v
     +---------------------------+
     |   Header & MIME Parser    |
     +-------------+-------------+
                   |
       +-----------+-----------+
       |                       |
       v                       v
+--------------+       +----------------+
| Auth Engine  |       | Content Engine |
| (SPF, DKIM,  |       | (URLs, Hops,   |
|   DMARC)     |       |  Attachments)  |
+-------+------+       +--------+-------+
        |                       |
        +-----------+-----------+
                    |
                    v
       +-------------------------+
       |  Defanging & IoC Hashes |
       | (MD5 / SHA256 / VT API) |
       +------------+------------+
                    |
                    v
       +-------------------------+
       |  Tier-1 Risk Scoring    |
       |  & Actionable Verdict   |
       +-------------------------+
```

---

## 🚀 Quickstart & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yogs011/phishing-email-analyzer.git
cd phishing-email-analyzer
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Usage Mode A: CLI Analysis (Fast Terminal Triage)
Run the script on any `.eml` file:
```bash
python analyzer.py samples/sample_malicious_phish.eml
```

### 4. Usage Mode B: Interactive Streamlit Dashboard
Launch the web interface locally:
```bash
streamlit run app.py
```
*Open your browser at `http://localhost:8501` to view the dashboard.*

---

## 🧪 Sample Artifacts Included

The repository comes with pre-configured sample emails in `samples/` for demonstration:
* `samples/sample_malicious_phish.eml`: A realistic credential-harvesting phishing attack with failed SPF/DKIM/DMARC, spoofed headers, direct IP links, and an executable attachment.
* `samples/sample_benign_newsletter.eml`: A legitimate, digitally signed digest from GitHub with passing authentication checks.

---

## 📊 Sample CLI Output

```text
=================================================================
        SOC TIER-1 EMAIL THREAT INVESTIGATION REPORT
        Tool Author: Yogesh Birla | Blue Team Portfolio
=================================================================

[+] 1. EMAIL METADATA & HEADERS:
  * Subject     : CRITICAL: Immediate Password Reset Required within 24 Hours
  * From        : Microsoft 365 Security Team <account-security@microsoft-verify.support>
  * To          : target.employee@enterprise.com
  * Date        : Tue, 27 Oct 2026 14:21:45 +0530
  * Return-Path : <bounce-collector@evilcorp.com>

[+] 2. AUTHENTICATION (SPF / DKIM / DMARC):
  * SPF Status  : FAIL
  * DKIM Status : FAIL
  * DMARC Status: FAIL

[+] 3. EXTRACTED URLS & DEFANGED IOCs (1 found):
  * hxxp://198[.]51[.]100[.]45/portal/login?id=83921 [IP-DIRECT]

[+] 4. ATTACHMENTS & ARTIFACT HASHES (1 found):
  * File   : Urgent_Security_Patch.exe (0.14 KB) [!] POTENTIAL THREAT
    SHA256 : 237f7ca1cbd0a3b92134c202cf058c1bfc61cd91589f89f794c32a88e744ce2d
    MD5    : 29eaa6d2f220c32c3e6cf3c4e2603dc7

[+] 5. TRIAGE VERDICT & RISK SCORE:
  * Risk Score  : 100 / 100
  * Classification: MALICIOUS / HIGH RISK
=================================================================
```

---

## 👤 Author

* **Name:** Yogesh Birla
* **GitHub:** [@yogs011](https://github.com/yogs011)
* **Focus:** Security Operations Center (SOC) / Threat Detection / Blue Teaming

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
