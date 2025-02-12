🚀 SmartPT-Assume-Breach


🔍 About SmartPT


SmartPT is a powerful cybersecurity solution designed to enhance security monitoring, automate incident response, and detect threats in real-time. It integrates Wazuh, XDR, and AI-driven analytics to protect businesses from cyber threats.


📢 All Wazuh alerts are sent to customers via WhatsApp 📢 📲


🛠 What This Repository Offers


This repository contains:


🔹 Custom Wazuh rules for advanced threat detection.
🔹 Active response mechanisms for automated incident mitigation.
🔹 Integration scripts for connecting Wazuh with popular XDR platforms.
🔹 Pre-built notification system using WhatsApp AI bots.


⚡ Use these configurations as-is, or contact us for professional services.



📂 Files & Configurations


📌 local.rules - Detects threats like privilege escalation, failed authentications, and ransomware attacks.


📌 ossec.conf - Defines automated active response mechanisms.


📌 agent.conf - Specifies directories and files for security monitoring.



🔥 Key Detection Rules


1️⃣ Admin Activity Monitoring


✅ Rule ID: 191111 - Detects new admin process execution (Privilege Escalation) [MITRE ID: T1078]
✅ Rule ID: 191117 - Detects unauthorized admin activity (Suspicious Access) [MITRE ID: T1078]


2️⃣ Authentication Monitoring


✅ Rule ID: 101010 - Detects unknown source logins (Potential Credential Compromise) [MITRE ID: T1078]
✅ Rule ID: 101011 - Detects failed logins (Brute-Force Attack) [MITRE ID: T1110]


3️⃣ Domain Admin Monitoring


✅ Rule ID: 100004 - Detects unauthorized domain admin activities (Privilege Escalation) [MITRE ID: T1078]


4️⃣ Command & Control (C2) Detection


✅ Rule ID: 111111 - Detects external C2 communication (Malicious Network Traffic) [MITRE ID: T1071]


5️⃣ Ransomware Detection


✅ Rule ID: 555555 - Detects abnormal file encryption (Potential Ransomware) [MITRE ID: T1486]



⚡ Automated Active Response


🚨 SmartPT_AI - AI-driven security analysis.
🚨 Users_and_groups_alerts - Monitors suspicious user modifications.
🚨 Admin_Process_Detection - Kills unauthorized admin processes.
🚨 network_access_violation_AIR - Isolates infected endpoints.



🚀 Quick Start


1️⃣ Copy & Apply local.rules, ossec.conf, agent.conf in Wazuh.
2️⃣ Restart Wazuh Services:


systemctl restart wazuh-manager



3️⃣ Monitor Alerts in Real-Time:


tail -f /var/ossec/logs/alerts/alerts.json




🌎 Learn More & Get Help
📢 Want more? Check out SmartPT Website 📲 for WhatsApp bot integration, AI-based security, and XDR solutions!



🤝 Contribute


We welcome community contributions! Submit issues, PRs, or suggestions to improve security detections and automation.



📜 License


This project is licensed under the MIT License.
