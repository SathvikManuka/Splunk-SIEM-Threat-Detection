# SIEM Detection Findings Report

**Generated:** 2024-01-15 10:30:00  
**Analyst:** Manuka Sathvik  
**Platform:** Splunk (Free Trial)  
**Log Sources:** DNS logs, HTTP access logs, Windows Event Logs (simulated)

---

## Executive Summary

Ran 5 detection rules against synthetic log data simulating a corporate environment under attack. Identified 3 confirmed threat scenarios and 1 suspicious activity requiring further investigation.

| Detection | Result | Severity | MITRE Technique |
|---|---|---|---|
| Brute Force Login | ✅ Detected | HIGH | T1110 |
| DNS C2 Communication | ✅ Detected | HIGH | T1071.004 |
| Privilege Escalation | ⚠️ Suspicious | MEDIUM | T1078 |
| Suspicious PowerShell | ✅ Detected | HIGH | T1059.001 |
| Anomalous HTTP Traffic | ✅ Detected | HIGH | T1071.001 / T1048.003 |

---

## Finding 1: Brute Force Attack — T1110

**Source IP:** `185.220.101[.]50`  
**Target:** `/login` endpoint  
**Failed attempts:** 6 in 7 seconds  
**Outcome:** Successful login on attempt 7

**Evidence from logs:**
```
185.220.101.50 POST /login 401 - 6 times in 7 seconds
185.220.101.50 POST /login 200 - success at 08:02:06
```

**SPL Alert triggered:** `brute_force.spl` — count=6, severity=MEDIUM escalated to HIGH after successful auth.

**Recommended Response (PICERL):**
- **Identify** — Confirmed brute force from `185.220.101[.]50`
- **Contain** — Block IP at WAF/firewall immediately
- **Eradicate** — Audit account for post-login activity
- **Recover** — Force password reset for compromised account
- **Lessons** — Implement account lockout after 3 failed attempts

---

## Finding 2: DNS C2 / DGA Activity — T1071.004

**Source IP:** `192.168.1[.]200` (internal endpoint — compromised)  
**Pattern:** 24 DNS queries to `*.c2server.ru` and `*.malicious-dga.com` in 5 minutes  
**Unique domains queried:** 24 (very high for a single endpoint)  
**NXDOMAIN ratio:** 58% (classic DGA pattern — malware trying multiple generated domains)

**SPL Alert triggered:** `dns_c2_detection.spl` — total_queries=24, unique_domains=24, ratio=1.0

**Recommended Response:**
- **Isolate** `192.168.1[.]200` from network immediately
- **Block** `c2server.ru` and `malicious-dga.com` at DNS resolver
- **Hunt** for lateral movement from this IP in the last 24 hours
- **Forensic** — memory dump and disk image for malware analysis

---

## Finding 3: Data Exfiltration over HTTP — T1048.003

**Source IP:** `185.220.101[.]50` (same attacker as Finding 1)  
**Path:** `/admin/export`, `/admin/logs`, `/admin/users`  
**Total data transferred:** ~8.5 MB in 5 minutes  
**Avg response size:** 786 KB per request (flagged as exfiltration)

**SPL Alert triggered:** `anomalous_http.spl` — avg_response_bytes=786432, severity=HIGH

**Timeline reconstruction:**
```
08:02:06  Successful brute force login       ← Finding 1
08:02:10  First admin endpoint access
08:02:12  /admin/export — bulk data pull
08:04:03  /admin/logs  — additional exfil
```

**Recommended Response:**
- Revoke session token immediately
- Audit what data was exported (`/admin/export` contents)
- Notify data protection officer (GDPR breach assessment)
- Review admin endpoint access controls

---

## Finding 4: Suspicious PowerShell — T1059.001

**Host:** `WORKSTATION-07`  
**User:** `jsmith`  
**Detected keywords:** `IEX`, `DownloadString`, `-enc`

Encoded PowerShell followed by a download cradle — consistent with a fileless malware dropper or post-exploitation framework (e.g., PowerShell Empire, Cobalt Strike).

**Recommended Response:**
- Isolate `WORKSTATION-07`
- Check for persistence (T1547 — Registry Run Keys)
- Review parent process of PowerShell (`explorer.exe` vs `winword.exe` — phishing delivery)

---

## Detection Performance

| Rule | True Positives | False Positives | Tuning Applied |
|---|---|---|---|
| Brute Force | 1 | 0 | Threshold: >5 failures |
| DNS C2 | 1 | 0 | Exclude known DNS servers |
| Privilege Escalation | 0 | 0 | No events in sample logs |
| Suspicious PowerShell | 1 | 0 | Keyword-based matching |
| Anomalous HTTP | 1 | 0 | >200 req + large response |

---

_Report generated as part of Splunk SIEM Threat Detection lab — github.com/SathvikManuka_
