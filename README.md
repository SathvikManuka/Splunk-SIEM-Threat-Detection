# 🛡️ Splunk SIEM Threat Detection

![Splunk](https://img.shields.io/badge/Splunk-SIEM-FF6B35?style=flat&logo=splunk&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Blue Team](https://img.shields.io/badge/Blue--Team-1E8449?style=flat)
![SPL](https://img.shields.io/badge/SPL-Detection%20Rules-orange?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

A Splunk-based threat detection lab simulating a SOC environment. Ingests DNS and HTTP logs, applies SPL detection rules to surface anomalous traffic patterns, and provides a unified dashboard to monitor alerts and Indicators of Compromise (IOCs) — all mapped to the MITRE ATT&CK framework.

---

## 🎯 Threat Scenarios Covered

| Scenario | MITRE ATT&CK Technique | Detection File |
|---|---|---|
| Brute Force Login Attempts | T1110 – Brute Force | `brute_force.spl` |
| DNS-based C2 Communication | T1071.004 – DNS | `dns_c2_detection.spl` |
| Privilege Escalation | T1078 – Valid Accounts | `privilege_escalation.spl` |
| Suspicious PowerShell Execution | T1059.001 – PowerShell | `suspicious_powershell.spl` |
| Anomalous HTTP Traffic | T1071.001 – Web Protocols | `anomalous_http.spl` |

---

## ⚙️ Features

- **Log Ingestion** — DNS and HTTP log pipelines built in Splunk
- **SPL Detection Rules** — 5 production-style detection queries with tuned thresholds and inline comments
- **MITRE ATT&CK Mapping** — every rule tagged to specific technique IDs
- **Dashboard** — 6-row unified view including headline counts, timeline, top IPs, per-detection tables, and hourly heatmap
- **Sample Logs** — synthetic DNS and HTTP logs included for immediate testing
- **Analysis Reports** — documented findings for each detection scenario

---

## 📁 Repository Structure

```
Splunk-SIEM-Threat-Detection/
├── brute_force.spl              # T1110  - Brute Force
├── dns_c2_detection.spl         # T1071.004 - DNS C2
├── privilege_escalation.spl     # T1078  - Valid Accounts
├── suspicious_powershell.spl    # T1059.001 - PowerShell
├── anomalous_http.spl           # T1071.001 - Web Protocols
├── threat_detection_dashboard.xml  # Splunk dashboard (import via UI)
├── dns_logs_sample.csv          # Synthetic DNS logs with C2 patterns
├── http_logs_sample.csv         # Synthetic HTTP logs with anomalies
├── detection_findings_report.md # Full analysis findings
└── README.md
```

---

## 🚀 Setup & Usage

### Prerequisites

- Splunk Free or Enterprise (v8.x+) — [Download here](https://www.splunk.com/en_us/download.html)

### 1. Ingest the sample logs

```
Settings → Add Data → Upload → select dns_logs_sample.csv
Settings → Add Data → Upload → select http_logs_sample.csv
```

Set sourcetype as `csv` and index as `main` for both files.

### 2. Run a detection query

Open **Search & Reporting**, paste any `.spl` file and hit Run:

```
Example: paste contents of brute_force.spl → Run
```

### 3. Import the dashboard

```
Dashboards → Create New Dashboard → Edit Source → paste contents of threat_detection_dashboard.xml → Save
```

The dashboard has 6 rows: headline counts, alert timeline, top IPs, per-detection tables, and an hourly heatmap.

---

## 🔍 Detection Rules

### 1. Brute Force Detection (`T1110`)

```spl
index=main sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
| where count > 5
| eval mitre_technique="T1110 - Brute Force"
| eval severity=if(count>20,"HIGH","MEDIUM")
| table src_ip, user, count, severity, mitre_technique
| sort -count
```

**Logic:** Counts failed SSH login attempts per source IP per user. Threshold of 5 failures = MEDIUM; 20+ = HIGH. Low threshold catches systematic attacks while staying above single-typo false positives.

---

### 2. DNS C2 Communication (`T1071.004`)

```spl
index=main sourcetype=dns
| stats count dc(query) as unique_domains by src_ip
| where count > 100 AND unique_domains > 50
| eval mitre_technique="T1071.004 - Application Layer Protocol: DNS"
| eval alert="Possible DNS C2 - High query volume with many unique domains"
| table src_ip, count, unique_domains, alert, mitre_technique
| sort -count
```

**Logic:** High DNS query volume combined with high unique domain count is a signature of DNS tunnelling or C2 beaconing (e.g., DGA-generated domains). Legitimate endpoints rarely resolve 50+ unique domains in a short window.

---

### 3. Privilege Escalation (`T1078`)

```spl
index=main sourcetype=WinEventLog EventCode=4672
| stats count by Account_Name, Logon_Type, src_ip
| where count > 3
| eval mitre_technique="T1078 - Valid Accounts"
| eval alert="Sensitive Privilege Assignment Detected"
| table Account_Name, Logon_Type, src_ip, count, alert, mitre_technique
| sort -count
```

**Logic:** Windows Event 4672 fires when special privileges are assigned at login. Multiple occurrences from the same account, especially from unexpected IPs, indicate privilege abuse or lateral movement via valid credentials.

---

### 4. Suspicious PowerShell (`T1059.001`)

```spl
index=main sourcetype=WinEventLog EventCode=4104
| search ScriptBlockText IN ("*-enc*","*bypass*","*hidden*","*DownloadString*","*IEX*","*Invoke-Expression*")
| stats count by ComputerName, User, ScriptBlockText
| eval mitre_technique="T1059.001 - Command and Scripting Interpreter: PowerShell"
| eval severity="HIGH"
| table ComputerName, User, ScriptBlockText, count, severity, mitre_technique
```

**Logic:** Event 4104 captures PowerShell script block logging. Keywords like `-enc` (base64-encoded commands), `bypass` (execution policy bypass), and `DownloadString` (payload download) are strong indicators of malicious PowerShell usage.

---

### 5. Anomalous HTTP Traffic (`T1071.001`)

```spl
index=main sourcetype=access_combined
| stats count avg(bytes) as avg_bytes by src_ip, uri_path, status
| where count > 200 AND status=200
| eval mitre_technique="T1071.001 - Application Layer Protocol: Web Protocols"
| eval alert=if(avg_bytes>500000,"Possible Data Exfiltration","High Volume HTTP")
| table src_ip, uri_path, count, avg_bytes, alert, mitre_technique
| sort -count
```

**Logic:** High-frequency successful HTTP requests to the same URI path — especially with large average response sizes — indicate web scraping, credential stuffing, or data exfiltration over HTTP.

---

## 📊 Dashboard Overview

The `threat_detection_dashboard.xml` file provides a 6-row unified SOC view:

| Row | Content |
|---|---|
| Row 1 | Headline single-value counts for all 5 detections (color-coded by severity) |
| Row 2 | Alert volume line chart over the last 24 hours, broken down by detection type |
| Row 3 | Top 10 attacking source IPs (bar chart) + Brute force targeted accounts (table) |
| Row 4 | DNS C2 beaconing IPs (table) + Privilege escalation flagged accounts (table) |
| Row 5 | Suspicious PowerShell executions (table) + Anomalous HTTP endpoints (table) |
| Row 6 | Stacked column chart — alert distribution by hour of day (last 7 days) |

To import: **Dashboards → Create New Dashboard → Edit Source → paste XML → Save**

---

## 🔧 Architecture

```
Sample Log Files (CSV)
        │
        ▼
  Splunk Indexer
  (index=main)
        │
        ├──► DNS Logs  (sourcetype=dns)
        ├──► HTTP Logs (sourcetype=access_combined)
        └──► Win Logs  (sourcetype=WinEventLog)
              │
              ▼
     SPL Detection Rules
              │
        ┌─────┴──────┐
        │            │
     Alerts      Dashboard
  (per query)  (unified view)
        │            │
        ▼            ▼
   MITRE ATT&CK  Analyst
     Mapping     Review
```

---

## 📚 Skills Demonstrated

- Splunk SIEM log ingestion and pipeline configuration
- SPL (Search Processing Language) for threat detection
- MITRE ATT&CK framework technique mapping
- Brute force, C2, privilege escalation, and PowerShell detection
- SOC alert triage and false positive threshold tuning
- Dashboard design for security operations

---

## 📄 License

MIT License — free to use for educational and research purposes.

---

> **Author:** Manuka Sathvik — [LinkedIn](https://linkedin.com/in/sathvik-manuka) · [GitHub](https://github.com/SathvikManuka)
