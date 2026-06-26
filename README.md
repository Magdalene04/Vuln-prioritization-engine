# Enterprise Vulnerability Assessment & Risk Prioritization Engine

## 📌 Project Overview
This project is an automated Python security pipeline that ingests raw network vulnerability scan data (Nmap XML format) and transforms it into a context-aware **Remediation Risk Matrix**. 

Instead of relying solely on generic industry-standard CVSS Base scores, this engine recalculates threat levels by evaluating critical asset environments against business context parameters: **Asset Criticality ($AC$)** and **Network Exposure ($NE$)**.

## 🧠 Risk Formula Architecture
The engine applies a custom weighted algorithm to map technical risks directly to business environments:

$$\text{True Business Risk Score} = \min(\text{Base CVSS} \times AC \times NE, 10.0)$$

* **Asset Criticality ($AC$):** Range [1.0 - 1.5] based on the data tier classification (e.g., core database or production commanding system).
* **Network Exposure ($NE$):** Range [0.8 - 1.2] based on perimeter boundary placement (e.g., public internet DMZ or hidden behind a secure localized firewall).

## 🛠️ Tech Stack & Environment
* **Development Language:** Python 3 (Built-in standard library components)
* **IDE:** VS Code (Windows 10 Base System)
* **Lab Environment:** Oracle VirtualBox
* **Attacking Target Profiles:** Kali Linux OS
* **Vulnerable Machine Testing Targets:** Metasploitable 2 VM / bWAPP

## 🚀 How It Works
1. **Ingest & Parse:** Slices through complex nested Nmap sub-element trees to isolate specific open network ports and cross-reference corresponding vulnerability script tables for verified CVE codes.
2. **Prioritize:** Drops structural metrics into the risk prioritization logic block.
3. **Sort & Filter:** Re-orders 800+ extracted targets into a clean Executive Top 10 remediation table.
4. **Data Delivery Export:** Writes the complete sorted matrix payload directly into a standardized `prioritized_risk_report.json` system file for immediate SIEM dashboard ingestion.