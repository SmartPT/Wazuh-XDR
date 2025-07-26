import os
import sys
import json
import re
import requests
from datetime import datetime, timedelta

LOG_FILE = "/var/ossec/logs/active-responses.log"
OUTPUT_FILE = "/var/ossec/logs/extracted_data.json"
THROTTLE_FILE = "/var/ossec/logs/throttle_tracker.json"
API_ENDPOINT = "https://dev.smartpt.co.il/Smartptdev"
THROTTLE_INTERVAL = timedelta(minutes=74400)
SHA256_KEY = "6f6e7909088faa9d31f43d9f03272c78817f7726b6621379adab515260f1fecb"

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{datetime.now()}] {message}\n")

def save_debug_log(raw_data, reason):
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    debug_dir = "/var/ossec/logs/debug"
    os.makedirs(debug_dir, exist_ok=True)
    file_path = f"{debug_dir}/{timestamp_str}_needtocheck.log"
    try:
        with open(file_path, "w") as f:
            f.write(f"// {reason}\n")
            f.write(raw_data + "\n")
        log_message(f"❌ Saved debug log to {file_path}")
    except Exception as e:
        log_message(f"❌ Failed to write debug log file: {e}")

def read_raw_file(file_path):
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        log_message(f"Error reading file: {e}")
        sys.exit(1)

def extract_throttle_keys(json_string):
    keys = {
        "agent_name": "N/A",
        "rule_id": "N/A",
        "timestamp": "N/A"
    }

    agent_match = re.search(r'"agent"\s*:\s*{[^}]*?"name"\s*:\s*"([^"]+)"', json_string, re.DOTALL)
    rule_match = re.search(r'"rule"\s*:\s*{[^}]*?"id"\s*:\s*"([^"]+)"', json_string, re.DOTALL)
    time_match = re.search(r'"timestamp"\s*:\s*"([^"]+)"', json_string)

    if agent_match:
        keys["agent_name"] = agent_match.group(1)
    if rule_match:
        keys["rule_id"] = rule_match.group(1)
    if time_match:
        keys["timestamp"] = time_match.group(1)

    return keys

def load_throttle_data():
    now = datetime.now()
    cleaned = {}

    if os.path.exists(THROTTLE_FILE):
        try:
            with open(THROTTLE_FILE, "r") as f:
                data = json.load(f)
                for key, timestamp in data.items():
                    try:
                        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        if now - t < THROTTLE_INTERVAL:
                            cleaned[key] = timestamp
                        else:
                            log_message(f"Throttle expired: {key}")
                    except ValueError:
                        log_message(f"Bad timestamp format: {key}")
        except Exception:
            log_message("Throttle file malformed. Starting fresh.")

    save_throttle_data(cleaned)
    return cleaned

def save_throttle_data(data):
    with open(THROTTLE_FILE, "w") as f:
        json.dump(data, f)

def should_throttle(agent_name, rule_id):
    if agent_name == "N/A" or rule_id == "N/A":
        return False  # Don't throttle if keys are bad
    throttle_data = load_throttle_data()
    key = f"{agent_name}_{rule_id}"
    now = datetime.now()
    last = throttle_data.get(key)
    if last:
        try:
            last_time = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
            if now - last_time < THROTTLE_INTERVAL:
                log_message(f"⏱️ Throttled: {key}")
                return True
        except ValueError:
            pass
    throttle_data[key] = now.strftime("%Y-%m-%d %H:%M:%S")
    save_throttle_data(throttle_data)
    return False

def post_to_api(raw_json, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        response = requests.post(API_ENDPOINT, headers=headers, data=raw_json.encode())
        log_message(f"📡 Sent to {API_ENDPOINT} | Status: {response.status_code}")
        log_message(f"🔁 Response: {response.text}")
    except Exception as e:
        log_message(f"❌ Failed to POST to API: {e}")

if __name__ == "__main__":
    log_message("🚀 Starting AI alert processor")

    if len(sys.argv) < 2:
        log_message("⚠️ No alert file passed.")
        sys.exit(1)

    ALERT_FILE = sys.argv[1]
    log_message(f"📥 Reading alert file: {ALERT_FILE}")

    if not os.path.exists(ALERT_FILE):
        log_message(f"⚠️ File does not exist: {ALERT_FILE}")
        sys.exit(1)

    raw_json = read_raw_file(ALERT_FILE)
    throttle_keys = extract_throttle_keys(raw_json)

    agent_name = throttle_keys.get("agent_name", "N/A")
    rule_id = throttle_keys.get("rule_id", "N/A")

    if should_throttle(agent_name, rule_id):
        sys.exit(0)  # Throttled alert, exit quietly

    try:
        with open(OUTPUT_FILE, "w") as out:
            out.write(raw_json)
        log_message(f"✅ Raw JSON written to {OUTPUT_FILE}")
    except Exception as e:
        log_message(f"❌ Failed writing raw output: {e}")
        save_debug_log(raw_json, f"Output write failed: {e}")
        sys.exit(1)

    post_to_api(raw_json, {
        'X-Email-Enabled': 'true',
        'X-Slack-Enabled': 'true',
        'X-slack_score_threshold': '5',
        'X-WhatsApp-Enabled': 'true',
        'X-Email-Score-Threshold': '5',
        'X-WhatsApp-Score-Threshold': '5',
        'X-Ticket-Email': 'eitanroz1@gmail.com',
        'X-Ticket-Email-Score-Threshold': '5',
        'X-Ticket-Email-Subject': 'Custom Security Alert Notification',
        'X-Source-System': 'production_firewall',
        'X-Attachment-Format': 'txt',
        'X-Sha256': SHA256_KEY,
        'X-Exclude-Ip-Range': '192.168.1.0/24,10.0.0.0/8',
        'X-Exclude-Keywords': 'maintenance,test',
        'X-logs-bucket': 'true'
    })
