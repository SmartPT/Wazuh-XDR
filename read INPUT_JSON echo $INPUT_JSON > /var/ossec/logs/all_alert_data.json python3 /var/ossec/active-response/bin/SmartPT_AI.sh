read INPUT_JSON
echo $INPUT_JSON > /var/ossec/logs/all_alert_data.json
python3 /var/ossec/active-response/bin/SmartPT_AI_v3.py
