import xml.etree.ElementTree as ET
import os

def parse_nmap_xml(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        return []

    print(f"[+] Successfully loaded {file_path}. Parsing data...")
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
                    # Look at all tables inside this vulnerability script
                    for table in script.findall('.//table'):
                        
                        # Fallback list to look for vulnerability identities
                        vuln_id = table.get('key')
                        cvss_score = 0.0
                        
                        # Deep check inside elements for keys like 'id', 'cve', or 'cvss'
                        for elem in table.findall('.//elem'):
                            elem_key = elem.get('key')
                            
                            if elem_key in ['id', 'cve'] and (not vuln_id or 'Unknown' in vuln_id or '/' in vuln_id):
                                vuln_id = elem.text
                            elif elem_key == 'cvss':
                                try:
                                    cvss_score = float(elem.text)
                                except (ValueError, TypeError):
                                    pass
                        
                        # Clean up strings if they are messy or missing
                        if not vuln_id:
                            vuln_id = "Unknown-Vuln"
                            
                        # If we have a valid score, log it!
                        if cvss_score > 0:
                            vuln_entry = {
                                "ip": ip_address,
                                "port": port_id,
                                "protocol": protocol,
                                "vuln_id": vuln_id,
                                "base_cvss": cvss_score
                            }
                            parsed_vulns.append(vuln_entry)
                            print(f"    [Found] Port {port_id} -> {vuln_id} (CVSS: {cvss_score})")
                            
    return parsed_vulns

if __name__ == "__main__":
    scan_file = "metasploitable_scan.xml"
    vulns = parse_nmap_xml(scan_file)
    print(f"\n[+] Extraction complete. Found {len(vulns)} total vulnerabilities.")