import re
import os
import sys
import json
import requests
from datetime import datetime, timedelta

LOG_FILE = "/var/ossec/logs/active-responses.log"
OUTPUT_FILE = "/var/ossec/logs/extracted_data.json"
THROTTLE_FILE = "/var/ossec/logs/throttle_tracker.json"
API_ENDPOINT = "https://xxx.smartpt.co.il/alerts"
THROTTLE_INTERVAL = timedelta(minutes=14400)
SHA256_KEY = "customer key"

def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{datetime.now()}] {message}\n")

def read_json_file(file_path):
    try:
        with open(file_path, "r") as json_file:
            return json_file.read()
    except Exception as e:
        log_message(f"Error reading JSON file: {e}")
        sys.exit(1)

def sanitize_json_string(raw_json):
    return re.sub(r'""+', '"', raw_json)

def extract_fields(json_string):
    extracted = {
        'timestamp': re.search(r'"timestamp"\s*:\s*"([^"]+)"', json_string),
        'description': re.search(r'"description"\s*:\s*"([^"]+)"', json_string),
        'agent_name': re.search(r'"agent"\s*:\s*{[^}]*?"name"\s*:\s*"([^"]+)"', json_string, re.DOTALL),
        'agent_id': re.search(r'"agent"\s*:\s*{[^}]*?"id"\s*:\s*"([^"]+)"', json_string, re.DOTALL),
        'agent_ip': re.search(r'"agent"\s*:\s*{[^}]*?"ip"\s*:\s*"([^"]+)"', json_string, re.DOTALL),
        'rule_id': re.search(r'"rule"\s*:\s*{[^}]*?"id"\s*:\s*"([^"]+)"', json_string, re.DOTALL)
    }
    return {k: (v.group(1) if v else "N/A") for k, v in extracted.items()}

def load_throttle_data():
    now = datetime.now()
    cleaned = {}

    if os.path.exists(THROTTLE_FILE):
        try:
            with open(THROTTLE_FILE, "r") as file:
                data = json.load(file)
                for key, timestamp in data.items():
                    try:
                        t = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        if now - t < THROTTLE_INTERVAL:
                            cleaned[key] = timestamp
                    except ValueError:
                        continue  # Skip malformed timestamp
        except json.JSONDecodeError:
            log_message(f"Error: Malformed JSON in {THROTTLE_FILE}")
            return {}

    save_throttle_data(cleaned)
    return cleaned


def save_throttle_data(throttle_data):
    with open(THROTTLE_FILE, "w") as json_file:
        json.dump(throttle_data, json_file)

def should_send_alert(agent_name, rule_id):
    if agent_name == "N/A" or rule_id == "N/A":
        return True
    throttle_data = load_throttle_data()
    current_time = datetime.now()
    key = f"{agent_name}_{rule_id}"
    if key in throttle_data:
        last_sent_time = datetime.strptime(throttle_data[key], "%Y-%m-%d %H:%M:%S")
        if current_time - last_sent_time < THROTTLE_INTERVAL:
            log_message(f"Throttled: {key} (Last: {last_sent_time})")
            return False
    throttle_data[key] = current_time.strftime("%Y-%m-%d %H:%M:%S")
    save_throttle_data(throttle_data)
    return True

def post_to_api(full_data):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(API_ENDPOINT, headers=headers, json=full_data)
        log_message(f"POST to {API_ENDPOINT} with data: {json.dumps(full_data)}")
        log_message(f"Response Status Code: {response.status_code}")
        log_message(f"Response Body: {response.text}")
    except Exception as e:
        log_message(f"Error posting to {API_ENDPOINT}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        log_message("⚠️ No alert file passed.")
        sys.exit(1)

    ALERT_FILE = sys.argv[1]
    log_message(f"🚀 Processing file: {ALERT_FILE}")

    if not os.path.exists(ALERT_FILE):
        log_message(f"⚠️ File not found: {ALERT_FILE}")
        sys.exit(1)

    raw_json = read_json_file(ALERT_FILE)
    raw_json = sanitize_json_string(raw_json)
    extracted = extract_fields(raw_json)
    agent_name = extracted.get("agent_name")
    rule_id = extracted.get("rule_id")

    if should_send_alert(agent_name, rule_id):
        try:
            full_data = json.loads(raw_json)
        except Exception:
            full_data = {"raw_body": raw_json}
        full_data["sha256"] = SHA256_KEY
        for k, v in extracted.items():
            if k not in full_data:
                full_data[k] = v
        with open(OUTPUT_FILE, "w") as output_file:
            json.dump(full_data, output_file)
        log_message(f"✅ Data written to {OUTPUT_FILE}")
        post_to_api(full_data)
    else:
        log_message("🛑 Alert skipped due to throttle")
