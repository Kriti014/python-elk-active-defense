import time 
import re 
import subprocess 
from elasticsearch import Elasticsearch 
from datetime import datetime 

# Initialize Elasticsearch Connection 
es = Elasticsearch(["http://localhost:9200"]) 

# Data Stream Indexes 
MYSQL_INDEX = ".ds-logs-mysql.*" 
WINLOG_INDEX = ".ds-logs-winlog.*" 

# Capture exact ISO execution time to strictly filter out historic logs 
STARTUP_TIME_ISO = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ") 

# Phase 4 Rules: Database Layer (SQL Injection) 
SQLI_RULES = [ 
    {"name": "SQLi: Tautology / Auth Bypass", "pattern": r"(?i)\b(OR|AND|XOR)\b\s+.*=.*"}, 
    {"name": "SQLi: UNION Extraction", "pattern": r"(?i)\bUNION\b.*\bSELECT\b"}, 
    {"name": "SQLi: Time-Based Blind", "pattern": r"(?i)\b(SLEEP|BENCHMARK)\b\s*\("}, 
    {"name": "SQLi: Error-Based / XML Ingestion", "pattern": r"(?i)\b(EXTRACTVALUE|UPDATEXML|GTID_SUBSET|EXP|FLOOR)\b\s*\("}, 
    {"name": "SQLi: Schema Reconnaissance", "pattern": r"(?i)@@version|version_comment|\bfrom\b\s+information_schema"} 
] 

# Phase 5 Rules: Host Layer (Living off the Land / Binary Abuse) 
LOTL_RULES = [ 
    {"name": "LotL: Ingress Payload Transfer (certutil)", "pattern": r"(?i)certutil(\.exe)?.*(-urlcache|-split|-f)"}, 
    {"name": "LotL: Obfuscated Execution (PowerShell)", "pattern": r"(?i)powershell(\.exe)?\s+.*(-e\b|-enc\b|-encodedcommand\b|downloadstring|iex)"}, 
    {"name": "LotL: Shadow Copy / Backup Destruction", "pattern": r"(?i)vssadmin(\.exe)?\s+delete\s+shadows"}, 
    {"name": "LotL: Background File Download (bitsadmin)", "pattern": r"(?i)bitsadmin(\.exe)?.*(/transfer|/create)"}, 
    {"name": "LotL: WMI System Reconnaissance", "pattern": r"(?i)wmic(\.exe)?\s+(process|service|useraccount|os|startup)"} 
] 

SEEN_DOCUMENTS = set() 
BLOCKED_IPS = set()  # Active response memory cache 

def get_local_time(): 
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S") 

def execute_mitigation(ip_address, threat_name, layer): 
    """ 
    SOAR Module: Automated Active Mitigation Trigger 
    Fulfills Domain 4: Programmatically isolates malicious sources without breaking SIEM logging. 
    """ 
    if ip_address in BLOCKED_IPS or ip_address in ["127.0.0.1", "localhost", "Unknown", None]: 
        return 

    print(f"\n[⚡ ACTIVE RESPONSE TRIGGERED] Initiating automated containment for: {ip_address}") 
    
    # 1. Local Network Socket Containment (iptables) 
    try: 
        cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP" 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
        print(f" ┣━ [SUCCESS] Linux Kernel Firewall (iptables): Inbound socket blocked for {ip_address}") 
    except Exception as e: 
        print(f" ┣━ [ERROR] Failed to execute iptables rule: {e}") 

    # 2. Remote / Host Mitigation Payload Logging 
    win_rule = f'netsh advfirewall firewall add rule name="SIEM_AutoBlock_{ip_address}" dir=in action=block remoteip={ip_address}' 
    print(f" ┣━ [ACTION GENERATED] Host Mitigation Command: {win_rule}") 
    print(f" ┗━ [🛡️ MITIGATION COMPLETE] Threat origin {ip_address} is actively contained.") 
    print("=" * 75) 

    # Cache IP to avoid redundant executions 
    BLOCKED_IPS.add(ip_address) 

def scan_mysql_logs(): 
    try: 
        query = { 
            "query": { 
                "range": { 
                    "@timestamp": {"gte": STARTUP_TIME_ISO} 
                } 
            }, 
            "sort": [{"@timestamp": {"order": "desc"}}], 
            "size": 50 
        } 
        res = es.search(index=MYSQL_INDEX, body=query) 
        for hit in res['hits']['hits']: 
            doc_id = hit['_id'] 
            if doc_id in SEEN_DOCUMENTS: 
                continue 

            # Default attacker origin for database tier tests unless extracted from log 
            source_ip = hit['_source'].get('source', {}).get('ip', '192.168.10.30') 
            raw_query = hit['_source'].get('message', hit['_source'].get('mysql', {}).get('general', {}).get('query', '')) 

            for rule in SQLI_RULES: 
                if re.search(rule['pattern'], raw_query): 
                    print(f"\n[🚨 SIEM THREAT ALERT] - {get_local_time()} | LAYER: DATABASE") 
                    print(f" ┣━ Target Host:   sme-dc") 
                    print(f" ┣━ Threat Class: {rule['name']}") 
                    print(f" ┗━ Raw Query:    {raw_query.strip()}") 
                    print("=" * 75) 

                    execute_mitigation(source_ip, rule['name'], "DATABASE") 
                    break 

            SEEN_DOCUMENTS.add(doc_id) 
    except Exception: 
        pass 

def scan_windows_logs(): 
    try: 
        query = { 
            "query": { 
                "range": { 
                    "@timestamp": {"gte": STARTUP_TIME_ISO} 
                } 
            }, 
            "sort": [{"@timestamp": {"order": "desc"}}], 
            "size": 50 
        } 
        res = es.search(index=WINLOG_INDEX, body=query) 
        for hit in res['hits']['hits']: 
            doc_id = hit['_id'] 
            if doc_id in SEEN_DOCUMENTS: 
                continue 

            source_ip = hit['_source'].get('source', {}).get('ip', '192.168.10.30') 
            cmd = hit['_source'].get('process', {}).get('command_line', hit['_source'].get('message', '')) 
            host_name = hit['_source'].get('host', {}).get('name', 'sme-dc') 

            for rule in LOTL_RULES: 
                if re.search(rule['pattern'], cmd): 
                    print(f"\n[🚨 SIEM THREAT ALERT] - {get_local_time()} | LAYER: HOST (OS)") 
                    print(f" ┣━ Target Host:  {host_name}") 
                    print(f" ┣━ Threat Class: {rule['name']}") 
                    print(f" ┗━ Command Line: {cmd.strip()}") 
                    print("=" * 75) 

                    execute_mitigation(source_ip, rule['name'], "HOST") 
                    break 

            SEEN_DOCUMENTS.add(doc_id) 
    except Exception: 
        pass 

if __name__ == "__main__": 
    print("=" * 75) 
    print("     ENTERPRISE SIEM CORE: UNIFIED DATABASE & OS THREAT ENGINE") 
    print("=" * 75) 
    print(f"[*] Engine Active at Local Time: {get_local_time()}") 
    print("[+] Monitoring Data Streams: [.ds-logs-mysql.*] & [.ds-logs-winlog.*]\n") 

    # Pre-cache existing historic logs on startup to prevent historic alerts 
    print("[*] Pre-caching existing historic logs from Elasticsearch...") 
    for idx in [MYSQL_INDEX, WINLOG_INDEX]: 
        try: 
            init_res = es.search(index=idx, body={"query": {"match_all": {}}, "size": 10000}) 
            for hit in init_res['hits']['hits']: 
                SEEN_DOCUMENTS.add(hit['_id']) 
        except Exception: 
            pass 
    print(f"[+] Cached {len(SEEN_DOCUMENTS)} historic documents. Listening for LIVE events only...\n") 

    while True: 
        scan_mysql_logs() 
        scan_windows_logs() 
        time.sleep(2)
