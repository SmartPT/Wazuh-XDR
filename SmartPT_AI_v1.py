import os
import sys
import json
import re
import requests
from datetime import datetime, timedelta

LOG_FILE = "/var/ossec/logs/active-responses.log"
ALERT_FILE = "/var/ossec/logs/all_alert_data.json"
OUTPUT_FILE = "/var/ossec/logs/extracted_data.json"
THROTTLE_FILE = "/var/ossec/logs/throttle_tracker.json"
API_ENDPOINT = "https://xxx.smartpt.co.il/aialerts"
THROTTLE_INTERVAL = timedelta(minutes=100)
SHA256_KEY = "customer key"

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{datetime.now()}] {message}\n")

def read_json_file(file_path):
    try:
        with open(file_path, "r") as json_file:
            return json_file.read()  # return raw string
    except Exception as e:
        log_message(f"Error reading JSON file: {e}")
        sys.exit(1)

# Regex patterns for throttle check
patterns = {
    'agent_name': r'"agent":{.*?"name":"(.*?)"',
    'rule_id': r'"rule":{.*?"id":"(.*?)"',
    'timestamp': r'"timestamp":"(.*?)"',
}

def extract_throttle_keys(json_string):
    extracted = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, json_string)
        extracted[key] = match.group(1) if match else "N/A"
    return extracted

def load_throttle_data():
    if os.path.exists(THROTTLE_FILE):
        try:
            with open(THROTTLE_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            log_message(f"Malformed throttle file.")
            return {}
    return {}

def save_throttle_data(throttle_data):
    with open(THROTTLE_FILE, "w") as file:
        json.dump(throttle_data, file)

def should_send_alert(agent_name, rule_id):
    if agent_name == "N/A" or rule_id == "N/A":
        log_message("Missing agent_name or rule_id")
        return False
    throttle_data = load_throttle_data()
    key = f"{agent_name}_{rule_id}"
    now = datetime.now()
    last = throttle_data.get(key)
    if last:
        last_time = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
        if now - last_time < THROTTLE_INTERVAL:
            log_message(f"Throttled alert for {key}")
            return False
    throttle_data[key] = now.strftime("%Y-%m-%d %H:%M:%S")
    save_throttle_data(throttle_data)
    return True

def post_to_api(data, custom_headers=None):
    headers = {"Content-Type": "application/json"}
    if custom_headers:
        headers.update(custom_headers)
    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=data)
        log_message(f"Sent to {API_ENDPOINT}, Status: {response.status_code}")
        log_message(f"Response: {response.text}")
    except Exception as e:
        log_message(f"Failed POST: {e}")

if __name__ == "__main__":
    log_message("Starting JSON-based alert forwarder")

    if not os.path.exists(ALERT_FILE):
        log_message("No alert data file.")
        sys.exit(1)

    raw_json = read_json_file(ALERT_FILE)
    throttle_keys = extract_throttle_keys(raw_json)

    agent_name = throttle_keys.get("agent_name", "N/A")
    rule_id = throttle_keys.get("rule_id", "N/A")

    if should_send_alert(agent_name, rule_id):
        try:
            full_data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            log_message(f"Failed to parse JSON before send: {e}")
            sys.exit(1)

        # Add SHA256 customer key
        full_data["sha256"] = SHA256_KEY

        # Save to file
        with open(OUTPUT_FILE, "w") as out:
            json.dump(full_data, out)

        log_message(f"Saved raw data with sha256 to {OUTPUT_FILE}")

        # Send to API
        post_to_api(full_data, {
            'X-Email-Enabled': 'true',
            'X-WhatsApp-Enabled': 'true',
            'X-Email-Score-Threshold': '6',
            'X-WhatsApp-Score-Threshold': '8',
            'X-Ticket-Email': 'soc@domain.com',
            'X-Ticket-Email-Score-Threshold': '8',
            'X-Ticket-Email-Subject': 'Custom Security Alert Notification',
            'X-Source-System': 'production_firewall',
            'X-Attachment-Format': 'txt',
            'X-Sha256': SHA256_KEY,
            'X-Exclude-Ip-Range': '192.168.1.0/24,10.0.0.0/8',
            'X-Exclude-Keywords': 'maintenance,test',
            'X-logs-bucket': 'true'
        })
    else:
        log_message(f"Alert not sent due to throttling.")
