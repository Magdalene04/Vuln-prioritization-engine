import xml.etree.ElementTree as ET
import os

def calculate_true_risk(base_cvss, asset_criticality, network_exposure):
    """
    Recalculates vulnerability severity based on business context.
    Ensures the maximum capped score never exceeds 10.0.
    """
    calculated_score = base_cvss * asset_criticality * network_exposure
    return round(min(calculated_score, 10.0), 2)

def parse_and_prioritize_xml(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        return []

    # Mock Enterprise Asset Context Database
    # Real-world scenario: This data would come from an Asset Management system (CMDB)
    asset_criticality = 1.4  # High Criticality (e.g., Production Server / Command System)
    network_exposure = 1.2   # High Exposure (e.g., Public Facing / Demilitarized Zone)

    print(f"[+] Loading {file_path}...")
    print(f"[Context] Simulating Enterprise Environment:")
    print(f"          -> Asset Criticality Factor: {asset_criticality}")
    print(f"          -> Network Exposure Factor: {network_exposure}\n")
    
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
                            # Run the risk prioritization math engine!
                            true_risk = calculate_true_risk(cvss_score, asset_criticality, network_exposure)
                            
                            vuln_entry = {
                                "ip": ip_address,
                                "port": port_id,
                                "vuln_id": vuln_id,
                                "base_cvss": cvss_score,
                                "true_risk": true_risk
                            }
                            parsed_vulns.append(vuln_entry)
                            
    return parsed_vulns

if __name__ == "__main__":
    scan_file = "metasploitable_scan.xml"
    prioritized_report = parse_and_prioritize_xml(scan_file)
    
    # Sort vulnerabilities by True Risk so the absolute highest priorities surface first
    prioritized_report.sort(key=lambda x: x['true_risk'], reverse=True)
    
    # Print out the Top 10 High Priority Items to focus on remediation
    print(f"[+] Prioritization Complete. Top 10 Critical Flaws to Patch First:")
    print(f"{'Port':<8} | {'Vulnerability ID':<16} | {'Base CVSS':<10} | {'True Risk Score':<15}")
    print("-" * 60)
    
    for item in prioritized_report[:10]:
        print(f"{item['port']:<8} | {item['vuln_id']:<16} | {item['base_cvss']:<10} | {item['true_risk']:<15}")