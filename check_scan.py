"""Check scan details from database"""
import sqlite3
import json

conn = sqlite3.connect('reports.db')
cursor = conn.cursor()

# Get the latest scan for 192.168.1.9
cursor.execute('''
    SELECT target_ip, risk_score, vulnerabilities, date 
    FROM scan_reports 
    WHERE target_ip = ? 
    ORDER BY id DESC 
    LIMIT 1
''', ('192.168.1.9',))

row = cursor.fetchone()

if row:
    print("=" * 60)
    print("SCAN DETAILS FOR 192.168.1.9")
    print("=" * 60)
    print(f"Target IP: {row[0]}")
    print(f"Risk Score: {row[1]}/100")
    print(f"Vulnerabilities: {row[2] if row[2] else 'None'}")
    print(f"Date: {row[3]}")
    print("=" * 60)
    
    if row[2]:
        vulns = row[2].split(', ')
        print(f"\nVulnerability Details ({len(vulns)} found):")
        for v in vulns:
            if v:
                print(f"  - {v}")
    
    # Check if ML was used by checking logs or last_scan_results.json
    try:
        with open('last_scan_results.json', 'r') as f:
            scan_data = json.load(f)
            for device in scan_data:
                if device.get('ip_address') == '192.168.1.9':
                    print("\nDetailed Scan Results:")
                    print(f"  Hostname: {device.get('hostname', 'N/A')}")
                    print(f"  Open Ports: {device.get('open_ports', [])}")
                    print(f"  Services: {len(device.get('services', []))}")
                    print(f"  Vulnerabilities: {len(device.get('vulnerabilities', []))}")
                    if device.get('services'):
                        print("\n  Services Found:")
                        for svc in device.get('services', []):
                            print(f"    - Port {svc.get('port')}: {svc.get('name')} ({svc.get('product', 'N/A')})")
                    break
    except FileNotFoundError:
        print("\nNote: last_scan_results.json not found")
else:
    print("No scan record found for 192.168.1.9")

conn.close()

