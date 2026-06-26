import xml.etree.ElementTree as ET
import os
import json

def calculate_true_risk(base_cvss, asset_criticality, network_exposure):
    calculated_score = base_cvss * asset_criticality * network_exposure
    return round(min(calculated_score, 10.0), 2)

def parse_and_prioritize_xml(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        return []

    # Mock Enterprise Asset Context Database
    asset_criticality = 1.4  
    network_exposure = 1.2   

    print(f"[+] Loading {file_path}...")
    print(f"[Context] Simulating Enterprise Environment...")
    
    parsed_vulns = []
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        ports_node = host.find('ports')
        if ports_node is None:
            continue
            
        for port in ports_node.findall('port'):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            
            for script in port.findall('script'):
                script_id = script.get('id')
                
                if 'vuln' in script_id or script_id == 'vulners':
                    for table in script.findall('.//table'):
                        vuln_id = table.get('key')
                        cvss_score = 0.0
                        
                        for elem in table.findall('.//elem'):
                            elem_key = elem.get('key')
                            if elem_key in ['id', 'cve'] and (not vuln_id or 'Unknown' in vuln_id or '/' in vuln_id):
                                vuln_id = elem.text
                            elif elem_key == 'cvss':
                                try:
                                    cvss_score = float(elem.text)
                                except (ValueError, TypeError):
                                    pass
                        
                        if not vuln_id:
                            vuln_id = "Unknown-Vuln"
                            
                        if cvss_score > 0:
                            true_risk = calculate_true_risk(cvss_score, asset_criticality, network_exposure)
                            
                            vuln_entry = {
                                "ip_address": ip_address,
                                "port": int(port_id),
                                "protocol": protocol,
                                "vulnerability_id": vuln_id,
                                "base_cvss": cvss_score,
                                "true_risk_score": true_risk
                            }
                            parsed_vulns.append(vuln_entry)
                            
    return parsed_vulns

def export_to_json(data, output_filename):
    """
    Exports the prioritized vulnerabilities list to a structured JSON file.
    """
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"\n[+] Success! Prioritized report exported to: {output_filename}")
    except Exception as e:
        print(f"[-] Failed to export JSON: {e}")

if __name__ == "__main__":
    scan_file = "metasploitable_scan.xml"
    output_report = "prioritized_risk_report.json"
    
    # 1. Parse and prioritize
    prioritized_report = parse_and_prioritize_xml(scan_file)
    
    # 2. Sort metrics high-to-low
    prioritized_report.sort(key=lambda x: x['true_risk_score'], reverse=True)
    
    # 3. Print out the Top 10 High Priority Items to terminal
    print(f"\n[+] Prioritization Complete. Top 10 Critical Flaws to Patch First:")
    print(f"{'Port':<8} | {'Vulnerability ID':<16} | {'Base CVSS':<10} | {'True Risk Score':<15}")
    print("-" * 60)
    for item in prioritized_report[:10]:
        print(f"{item['port']:<8} | {item['vulnerability_id']:<16} | {item['base_cvss']:<10} | {item['true_risk_score']:<15}")

    # 4. Export full report to file system
    export_to_json(prioritized_report, output_report)