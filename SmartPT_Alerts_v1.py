import re
import os
import sys
import json
import requests
from datetime import datetime, timedelta

LOG_FILE = "/var/ossec/logs/active-responses.log"
ALERT_FILE = "/var/ossec/logs/all_alert_data.json"
OUTPUT_FILE = "/var/ossec/logs/extracted_data.json"
THROTTLE_FILE = "/var/ossec/logs/throttle_tracker.json"
API_ENDPOINT = "https://xxx.smartpt.co.il/alerts"
THROTTLE_INTERVAL = timedelta(minutes=180)
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

# 💡 Attempt to fix malformed JSON (e.g., ""text"" instead of "text")
def sanitize_json_string(raw_json):
    # Fix common error of duplicated quotes inside strings
    sanitized = re.sub(r'""+', '"', raw_json)
    return sanitized

# ✅ Regex patterns to extract required fields
patterns = {
    'alert_id': r'"id":"(.*?)"',
    'timestamp': r'"timestamp":"(.*?)"',
    'description': r'"description":"(.*?)"',
    'agent_name': r'"agent":{.*?"name":"(.*?)"',
    'agent_id': r'"agent":{.*?"id":"(.*?)"',
    'agent_ip': r'"agent":{.*?"ip":"(.*?)"',
    'rule_id': r'"rule":{.*?"id":"(.*?)"',
}

def extract_fields(json_string):
    extracted = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, json_string, re.DOTALL)
        extracted[key] = match.group(1) if match else "N/A"
    return extracted

def load_throttle_data():
    if os.path.exists(THROTTLE_FILE):
        try:
            with open(THROTTLE_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            log_message(f"Error: Malformed JSON in {THROTTLE_FILE}")
            return {}
    return {}

def save_throttle_data(throttle_data):
    with open(THROTTLE_FILE, "w") as json_file:
        json.dump(throttle_data, json_file)

def should_send_alert(agent_name, rule_id):
    if agent_name == "N/A" or rule_id == "N/A":
        log_message(f"Invalid agent_name ({agent_name}) or rule_id ({rule_id}), skipping alert.")
        return False

    throttle_data = load_throttle_data()
    current_time = datetime.now()
    key = f"{agent_name}_{rule_id}"

    if key in throttle_data:
        last_sent_time = datetime.strptime(throttle_data[key], "%Y-%m-%d %H:%M:%S")
        if current_time - last_sent_time < THROTTLE_INTERVAL:
            log_message(f"Alert throttled for {key}. Last sent at {last_sent_time}.")
            return False

    throttle_data[key] = current_time.strftime("%Y-%m-%d %H:%M:%S")
    save_throttle_data(throttle_data)
    return True

def post_to_api(full_data):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(API_ENDPOINT, headers=headers, json=full_data)

        log_message(f"POST to {API_ENDPOINT} with data: {json.dumps(full_data, indent=4)}")
        log_message(f"Response Status Code: {response.status_code}")
        log_message(f"Response Body: {response.text}")

        if response.status_code != 200:
            log_message(f"❌ Failed to post data to {API_ENDPOINT}: {response.status_code}")
        else:
            log_message(f"✅ Data successfully posted to {API_ENDPOINT}")
    except Exception as e:
        log_message(f"Error posting data to {API_ENDPOINT}: {e}")

if __name__ == "__main__":
    log_message("🚀 Starting alert processor")

    if not os.path.exists(ALERT_FILE):
        log_message("⚠️ Alert data file not found.")
        sys.exit(1)

    raw_json = read_json_file(ALERT_FILE)
    raw_json = sanitize_json_string(raw_json)  # ← תיקון לפני המשך

    extracted_fields = extract_fields(raw_json)

    agent_name = extracted_fields.get("agent_name")
    rule_id = extracted_fields.get("rule_id")

    if should_send_alert(agent_name, rule_id):
        try:
            full_data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            log_message(f"❌ Invalid JSON format in alert file even after sanitize: {e}")
            sys.exit(1)

        # Inject SHA256
        full_data["sha256"] = SHA256_KEY

        # Ensure all required extracted fields are present in full_data
        for key, value in extracted_fields.items():
            if key not in full_data or not full_data[key]:
                full_data[key] = value

        # Save full JSON to output file
        with open(OUTPUT_FILE, "w") as output_file:
            json.dump(full_data, output_file)
        log_message(f"✅ Full alert data saved to {OUTPUT_FILE}")

        # Send to API
        post_to_api(full_data)
    else:
        log_message(f"⛔ Alert not sent due to throttle for rule ID {rule_id} from agent {agent_name}.")
