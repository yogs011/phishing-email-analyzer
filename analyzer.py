"""
Automated Phishing & Email Threat Analyzer
Author: Yogesh Birla (github.com/yogs011)
Description: A SOC Tier-1 triage utility to parse .eml artifacts, evaluate 
             email authentication (SPF/DKIM/DMARC), defang indicators of compromise 
             (IoCs), and correlate attachment hashes with threat intelligence.
"""

import email
from email import policy
import re
import hashlib
import os
import sys
import json

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class EmailThreatAnalyzer:
    """Core analysis engine for inspecting raw email messages."""

    def __init__(self, eml_path: str, vt_api_key: str = None):
        self.eml_path = eml_path
        self.vt_api_key = vt_api_key or os.getenv("VT_API_KEY")
        self.msg = None
        self.results = {
            "metadata": {},
            "auth": {},
            "headers": {},
            "urls": [],
            "attachments": [],
            "risk_score": 0,
            "risk_factors": [],
            "verdict": "BENIGN"
        }

    def load_message(self):
        """Loads and parses the .eml file."""
        if not os.path.exists(self.eml_path):
            raise FileNotFoundError(f"EML file not found at: {self.eml_path}")
        
        with open(self.eml_path, "rb") as f:
            self.msg = email.message_from_binary_file(f, policy=policy.default)

    def extract_headers(self):
        """Extracts standard and security-relevant headers."""
        self.results["headers"] = {
            "Subject": self.msg.get("Subject", "(No Subject)"),
            "From": self.msg.get("From", "Unknown"),
            "To": self.msg.get("To", "Unknown"),
            "Date": self.msg.get("Date", "Unknown"),
            "Return-Path": self.msg.get("Return-Path", "Not specified"),
            "Reply-To": self.msg.get("Reply-To", "Not specified"),
            "Message-ID": self.msg.get("Message-ID", "Not specified"),
            "Received": self.msg.get_all("Received", [])
        }

        # Check for From vs Return-Path / Reply-To mismatch (classic spoofing indicator)
        from_header = self.results["headers"]["From"].lower()
        return_path = self.results["headers"]["Return-Path"].lower()
        reply_to = self.results["headers"]["Reply-To"].lower()

        if return_path != "not specified" and return_path not in from_header:
            self.results["risk_factors"].append("Mismatch detected between 'From' and 'Return-Path' headers (potential spoofing).")
            self.results["risk_score"] += 20

        if reply_to != "not specified" and reply_to not in from_header:
            self.results["risk_factors"].append("Discrepancy observed between 'From' and 'Reply-To' addresses.")
            self.results["risk_score"] += 15

    def check_authentication(self):
        """Parses SPF, DKIM, and DMARC verification results."""
        auth_header = self.msg.get("Authentication-Results", "")
        received_spf = self.msg.get("Received-SPF", "")
        combined_auth = (auth_header + " " + received_spf).lower()

        # SPF Evaluation
        if "spf=pass" in combined_auth or "pass" in received_spf.lower():
            spf_status = "PASS"
        elif "spf=fail" in combined_auth or "fail" in received_spf.lower():
            spf_status = "FAIL"
            self.results["risk_factors"].append("SPF validation failed: Originating mail server is not authorized to send on behalf of the domain.")
            self.results["risk_score"] += 25
        elif "spf=softfail" in combined_auth:
            spf_status = "SOFTFAIL"
            self.results["risk_factors"].append("SPF validation returned softfail (suspicious sender IP alignment).")
            self.results["risk_score"] += 15
        else:
            spf_status = "NONE / NOT DETECTED"
            self.results["risk_score"] += 5

        # DKIM Evaluation
        if "dkim=pass" in combined_auth:
            dkim_status = "PASS"
        elif "dkim=fail" in combined_auth:
            dkim_status = "FAIL"
            self.results["risk_factors"].append("DKIM cryptographic signature verification failed (message integrity compromised).")
            self.results["risk_score"] += 25
        else:
            dkim_status = "NONE / NOT DETECTED"
            self.results["risk_score"] += 5

        # DMARC Evaluation
        if "dmarc=pass" in combined_auth:
            dmarc_status = "PASS"
        elif "dmarc=fail" in combined_auth:
            dmarc_status = "FAIL"
            self.results["risk_factors"].append("DMARC alignment failure: Senders failed both domain alignment & authentication policy.")
            self.results["risk_score"] += 30
        else:
            dmarc_status = "NONE / NOT DETECTED"

        self.results["auth"] = {
            "SPF": spf_status,
            "DKIM": dkim_status,
            "DMARC": dmarc_status,
            "Raw": auth_header[:250] if auth_header else "No Authentication-Results header found."
        }

    def defang(self, text: str) -> str:
        """Defangs URLs and IP addresses to prevent accidental click-throughs."""
        return (
            text.replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace(".", "[.]")
        )

    def extract_urls(self):
        """Scans the email body for embedded hyperlinks and defangs them."""
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(errors="ignore")
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")

        # Find raw HTTP/HTTPS links
        raw_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", body)
        seen = set()

        for u in raw_urls:
            clean_u = u.strip().rstrip(".,;)")
            if clean_u not in seen:
                seen.add(clean_u)
                self.results["urls"].append({
                    "original": clean_u,
                    "defanged": self.defang(clean_u),
                    "is_ip_based": bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", clean_u))
                })

        # Check for IP-based URLs (often used in phishing to bypass domain filtering)
        ip_links = [x for x in self.results["urls"] if x["is_ip_based"]]
        if ip_links:
            self.results["risk_factors"].append(f"Detected {len(ip_links)} direct IP-address URL(s), a common indicator of credential harvesting.")
            self.results["risk_score"] += 25

        if len(self.results["urls"]) > 5:
            self.results["risk_factors"].append("High volume of external hyperlinks embedded within the body.")
            self.results["risk_score"] += 10

    def analyze_attachments(self):
        """Extracts file attachments and generates cryptographic hashes for IoC correlation."""
        high_risk_extensions = [".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".hta", ".js", ".wsf", ".zip"]

        for part in self.msg.walk():
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""

                md5 = hashlib.md5(payload).hexdigest()
                sha256 = hashlib.sha256(payload).hexdigest()
                size_kb = round(len(payload) / 1024, 2)

                ext = os.path.splitext(filename)[1].lower()
                is_dangerous = ext in high_risk_extensions

                if is_dangerous:
                    self.results["risk_factors"].append(f"Dangerous attachment file type detected: {filename} ({ext})")
                    self.results["risk_score"] += 35

                self.results["attachments"].append({
                    "filename": filename,
                    "extension": ext,
                    "size_kb": size_kb,
                    "md5": md5,
                    "sha256": sha256,
                    "is_dangerous": is_dangerous
                })

    def query_virustotal_hash(self, sha256: str) -> dict:
        """Queries VirusTotal v3 API for file hash reputation (optional)."""
        if not self.vt_api_key or not REQUESTS_AVAILABLE:
            return {"status": "skipped", "message": "VT_API_KEY not configured or requests missing."}

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"status": "success", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
            elif resp.status_code == 404:
                return {"status": "unknown", "message": "Hash not found in VirusTotal database."}
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return {"status": "error", "code": resp.status_code}

    def compute_final_verdict(self):
        """Assigns the final SOC Tier-1 incident classification."""
        score = min(self.results["risk_score"], 100)
        self.results["risk_score"] = score

        if score >= 60:
            self.results["verdict"] = "MALICIOUS / HIGH RISK"
        elif score >= 25:
            self.results["verdict"] = "SUSPICIOUS (Needs L2 Triage)"
        else:
            self.results["verdict"] = "BENIGN / LOW RISK"

    def run_all(self):
        """Executes full triage workflow."""
        self.load_message()
        self.extract_headers()
        self.check_authentication()
        self.extract_urls()
        self.analyze_attachments()
        self.compute_final_verdict()
        return self.results


def print_cli_report(results: dict):
    """Outputs a clean, professional SOC terminal report."""
    print("=" * 65)
    print("        SOC TIER-1 EMAIL THREAT INVESTIGATION REPORT")
    print("        Tool Author: Yogesh Birla | Blue Team Portfolio")
    print("=" * 65)

    headers = results["headers"]
    print("\n[+] 1. EMAIL METADATA & HEADERS:")
    print(f"  * Subject     : {headers.get('Subject')}")
    print(f"  * From        : {headers.get('From')}")
    print(f"  * To          : {headers.get('To')}")
    print(f"  * Date        : {headers.get('Date')}")
    print(f"  * Return-Path : {headers.get('Return-Path')}")

    auth = results["auth"]
    print("\n[+] 2. AUTHENTICATION (SPF / DKIM / DMARC):")
    print(f"  * SPF Status  : {auth.get('SPF')}")
    print(f"  * DKIM Status : {auth.get('DKIM')}")
    print(f"  * DMARC Status: {auth.get('DMARC')}")

    urls = results["urls"]
    print(f"\n[+] 3. EXTRACTED URLS & DEFANGED IOCs ({len(urls)} found):")
    for u in urls[:5]:
        print(f"  * {u['defanged']} {'[IP-DIRECT]' if u['is_ip_based'] else ''}")
    if len(urls) > 5:
        print(f"  ... and {len(urls) - 5} more links omitted for brevity.")

    attachments = results["attachments"]
    print(f"\n[+] 4. ATTACHMENTS & ARTIFACT HASHES ({len(attachments)} found):")
    if attachments:
        for att in attachments:
            flag = "[!] POTENTIAL THREAT" if att['is_dangerous'] else "[*] Clean format"
            print(f"  * File   : {att['filename']} ({att['size_kb']} KB) {flag}")
            print(f"    SHA256 : {att['sha256']}")
            print(f"    MD5    : {att['md5']}")
    else:
        print("  * No file attachments detected in this message.")

    print("\n[+] 5. TRIAGE VERDICT & RISK SCORE:")
    print(f"  * Risk Score  : {results['risk_score']} / 100")
    print(f"  * Classification: {results['verdict']}")
    if results["risk_factors"]:
        print("  * Identified Risk Indicators:")
        for factor in results["risk_factors"]:
            print(f"    - {factor}")
    print("=" * 65)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path_to_email.eml> [optional_vt_api_key]")
        sys.exit(1)

    eml_file = sys.argv[1]
    vt_key = sys.argv[2] if len(sys.argv) > 2 else None

    analyzer = EmailThreatAnalyzer(eml_file, vt_key)
    res = analyzer.run_all()
    print_cli_report(res)
