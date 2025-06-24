#!/bin/bash

# Path to the Wazuh alerts file
ALERT_FILE="/var/ossec/logs/alerts/alerts.json"
# Maximum allowed minutes since last log update
MAX_AGE_MINUTES=1

# Server identity
AGENT_NAME=$(hostname)
AGENT_IP=$(hostname -I | awk '{print $1}')
AGENT_ID="000"
RULE_ID="100"

# Check if alert file exists
if [ ! -f "$ALERT_FILE" ]; then
  echo "Alert file not found: $ALERT_FILE" >&2
  exit 2
fi

# Get last modification time
last_mod=$(stat -c %Y "$ALERT_FILE")
now=$(date +%s)
age=$(( (now - last_mod) / 60 ))

# If file hasn't been updated in too long, send alert JSON and restart services
if [ "$age" -ge "$MAX_AGE_MINUTES" ]; then
  cat <<EOF
{
  "agent_name": "$AGENT_NAME",
  "agent_id": "$AGENT_ID",
  "agent_ip": "$AGENT_IP",
  "rule_id": "$RULE_ID",
  "description": "Wazuh alert log has not been updated in $age minutes"
}
EOF

  # Restart Wazuh services
  systemctl restart wazuh-manager
  systemctl restart wazuh-indexer

  exit 0
fi

# No alert needed
exit 0


#send alerts by 
#*/10 * * * * /root/Wazuh-Scripts/wazuh_maintenance.sh |/usr/bin/python3 /var/ossec/active-response/bin/Smartpt_forwarde>
