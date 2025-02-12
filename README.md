🚀 SmartPT-Assume-Breach


🔍 What is SmartPT?


SmartPT is an advanced cybersecurity solution designed to protect businesses from modern threats using automated response, real-time detection, and seamless integration with existing security infrastructures.


🔥 SmartPT Kill Chain Protection


SmartPT helps organizations cover the entire attack lifecycle by proactively detecting and stopping threats at multiple stages:


Phishing & C2 Traffic – Detect and block C2 connections before attackers gain control.
Privilege Escalation – Prevent unauthorized local admin elevation with automatic mitigation.
Lateral Movement – Monitor and stop lateral movement attempts on endpoints & servers.
New Domain Admins – Block unauthorized domain admin creation and notify security teams.
Ransomware Protection – Detect ransomware behaviors and isolate infected machines in real-time.
Exfiltration Protection – Identify and prevent unauthorized file transfers to external servers.



🚀 SmartPT Integration Steps (Zero to Hero)


Follow these 5 essential steps to transform your security posture with SmartPT:


1️⃣ Install Wazuh & Sysmon – Set up Wazuh XDR for security monitoring and deploy Sysmon for advanced event logging.


2️⃣ Deploy SmartPT Detection Rules – Set up SmartPT Assume Breach rules, including privilege escalation, ransomware, and exfiltration detection.


3️⃣ Enable WhatsApp Alerts & AI Analysis – Integrate SmartPT with Wazuh XDR and other leading XDR solutions to enable risk-based AI alerts and custom security alerts via WhatsApp bot.


4️⃣ Register API for Active Response – Submit XDR API details to enable remote security commands via WhatsApp bot or the SmartPT platform.


5️⃣ Automate Security Response – Use Wazuh XDR automation to isolate compromised machines, terminate unauthorized processes, and log off at-risk users in Citrix or VDI environments.



📂 SmartPT Rules & Active Response Scripts


This repository contains:


🔹 Custom Wazuh rules for detecting privilege escalation, ransomware, C2 traffic, and unauthorized access.
🔹 Active response scripts to isolate infected machines and kill malicious processes.
🔹 Integration scripts for Wazuh-to-XDR connectivity.



📌 Key SmartPT Detection Rules


✅ Rule ID: 191111 – Detects new admin process execution (Privilege Escalation) [MITRE ID: T1078]
✅ Rule ID: 191117 – Detects unauthorized admin activity (Suspicious Access) [MITRE ID: T1078]
✅ Rule ID: 101010 – Detects unknown source logins (Potential Credential Compromise) [MITRE ID: T1078]
✅ Rule ID: 101011 – Detects failed logins (Brute-Force Attack) [MITRE ID: T1110]
✅ Rule ID: 100004 – Detects unauthorized domain admin activities (Privilege Escalation) [MITRE ID: T1078]
✅ Rule ID: 111111 – Detects external C2 communication (Malicious Network Traffic) [MITRE ID: T1071]
✅ Rule ID: 555555 – Detects abnormal file encryption (Potential Ransomware) [MITRE ID: T1486]



⚡ Automated Active Response Scripts


This repository includes pre-built Wazuh AR scripts:
🚨 SmartPT_AI – AI-driven security analysis.
🚨 Users_and_groups_alerts – Monitors suspicious user modifications.
🚨 Admin_Process_Detection – Kills unauthorized admin processes.
🚨 network_access_violation_AIR – Isolates infected endpoints automatically.



📲 WhatsApp AI Security Notifications


All Wazuh alerts are sent to customers via WhatsApp AI bots, providing:
✅ Real-time security alerts
✅ Automated response commands
✅ Customizable security notifications



🌎 Learn More & Get Help


📢 Visit SmartPT Website for WhatsApp bot integration, AI-driven security, and professional cybersecurity consulting!



📜 License


This project is licensed under the MIT License.
