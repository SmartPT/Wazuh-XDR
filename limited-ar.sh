#!/bin/bash
###############################################################################
# limited-ar.sh
# • Reads an alert JSON file (first arg or default path)
# • Allows max 5 different agent.id values per rolling hour
# • Re-runs are allowed for the same agent.id inside that window
###############################################################################

# 1) Where is the JSON?
INPUT_FILE=${1:-/var/ossec/logs/ransomware.json}

if [[ ! -r "$INPUT_FILE" ]]; then
    echo "ERROR: Cannot read JSON input file: $INPUT_FILE" >&2
    exit 1
fi

INPUT_JSON=$(cat "$INPUT_FILE")

# 2) Pull agent.id  ─ "agent":{ … "id":"VALUE"
AGENT_ID=$(printf '%s\n' "$INPUT_JSON" | grep -oP '"agent":\{.*?"id":"\K[^"]+')

if [[ -z "$AGENT_ID" ]]; then
    echo "ERROR: agent.id not found in JSON" >&2
    exit 1
fi
echo "agent.id = $AGENT_ID"

# 3) Paths / constants
AR_SCRIPT="/var/ossec/active-response/bin/cortex_ransomware.sh"
LOG_FILE="/tmp/python_agent_log.txt"
TIME_WINDOW=3600          # seconds (1 hour)
NOW=$(date +%s)

# 4) Keep only log entries from the last hour
touch "$LOG_FILE"
awk -v now="$NOW" -v w="$TIME_WINDOW" '$1 > now - w' "$LOG_FILE" > "$LOG_FILE.tmp"
mv "$LOG_FILE.tmp" "$LOG_FILE"

# 5) Metrics
UNIQUE_COUNT=$(awk '{print $2}' "$LOG_FILE" | sort -u | wc -l)
AGENT_ALREADY_RAN=$(awk -v id="$AGENT_ID" '$2==id' "$LOG_FILE" | wc -l)

# 6) Enforcement
if [[ "$UNIQUE_COUNT" -lt 5 || "$AGENT_ALREADY_RAN" -gt 0 ]]; then
    echo "$NOW $AGENT_ID" >> "$LOG_FILE"
    bash "$AR_SCRIPT"
else
    echo "Execution limit reached (5 unique agent.id per hour). Try again later."
fi
