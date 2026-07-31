
# Automated Threat Hunting & Active Response using ELK Stack and Python for Resource-Constrained SMEs

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Elasticsearch](https://img.shields.io/badge/Elastic-8.x-005571)](https://www.elastic.co/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An automated Detection, Incident Response, and Security Orchestration (SOAR) platform designed for resource-constrained SME environments. Built using Python, Elastic Stack, and custom active-response mitigation scripts to bridge the Cybersecurity Poverty Line.

## 📊 Key Operational Impact
- **82.27% MTTC Reduction:** Lowered incident response latency from **64.34s (manual)** down to **11.41s (automated)**.
- **Cross-Layer Defense:** Automated mitigation against both **Database layer (SQLi)** and **Host layer (Living-off-the-Land / LotL)** attack vectors.
- **Resource Optimized:** Engineered to run smoothly on constrained host resources (JVM heap capped at 1GB).

---

## 🏗 System Architecture & Topology

The environment consists of an isolated 3-node virtual laboratory:
1. **Attacker Node (Kali Linux):** 192.168.10.30
2. **Victim Endpoint (Windows Server 2022 + Sysmon):** 192.168.10.20
3. **SIEM & Response Engine (Ubuntu 22.04 + Elasticsearch + Python SOAR):** 192.168.10.10

```text
[ Kali Linux (Attacker) ] ──(Attacks)──► [ Windows / MySQL Target ] ──(Elastic Agent Logs)──► [ Elasticsearch ]
                                                                                                    │
[ Active Defense / Firewall ] ◄──(SOAR Socket Block / netsh)────────────────────────────────────────┤ Python Engine

```

---

## 🎯 Threat Detection & Mitigation Matrix

| Threat Class | Layer | Signature Pattern | MITRE ATT&CK | SOAR Response |
| :--- | :--- | :--- | :--- | :--- |
| **SQLi (Auth Bypass)** | Database | `(?i)\b(OR\|AND\|XOR)\b\s+.*=.*` | `T1190` | Socket Drop (`iptables`) |
| **SQLi (UNION Extract)** | Database | `(?i)\bUNION\b.*\bSELECT\b` | `T1190` / `T1005` | Socket Drop (`iptables`) |
| **SQLi (Schema Recon)** | Database | `(?i)@@version\|version_comment\|\bfrom\b\s+information_schema` | `T1082` | Socket Drop (`iptables`) |
| **LotL (Certutil)** | Host (Sysmon 1) | `(?i)certutil(\.exe)?.*(-urlcache\|-split)` | `T1105` | Firewall Block (`netsh`) |
| **LotL (Bitsadmin)** | Host (Sysmon 1) | `(?i)bitsadmin(\.exe)?.*(/transfer\|/create)` | `T1197` | Firewall Block (`netsh`) |
| **LotL (WMIC Recon)** | Host (Sysmon 1) | `(?i)wmic(\.exe)?\s+(process\|service)` | `T1047` / `T1082` | Firewall Block (`netsh`) |

---

## 🚀 Key Technical Features

* **Centralized Telemetry Pipeline:** Aggregates database and host telemetry via Elastic Agent stream.
* **Low-Overhead Regex Engine:** Parses real-time Elastic indices directly without UI polling delays.
* **Automated Endpoint Isolation:** Executes direct API/Socket orchestration to drop malicious traffic automatically upon detection.

---

## ⚙️ How to Run & Deploy

1. **Prerequisites:** Python 3.10+, Elasticsearch 8.x, and Elastic Agent with Sysmon installed on target hosts.
2. **Setup Environment:**
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/automated-soar-elk-sme.git](https://github.com/YOUR_GITHUB_USERNAME/automated-soar-elk-sme.git)
cd automated-soar-elk-sme
pip install elasticsearch

```

3. **Configure Connection:** Update host IP address and Elasticsearch connection details in `src/sqli_detector.py`.
4. **Execute Engine:**
```bash
python3 src/soar_detector.py

```
---

## 📄 Academic Research

This repository is the practical realization of my final dissertation: *"Automated Threat Hunting & Active Response using ELK (Elasticsearch, Logstash, Kibana) Stack and Python for Resource-Constrained SMEs"*. The complete research paper detailing methodology, mathematical proofs, and experimental trial matrices can be found in the `/docs` folder.

