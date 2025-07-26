#!/bin/bash

# ✅ First: read the JSON from stdin into a variable
read INPUT_JSON

# ✅ Save it to a timestamped file
DATESTAMP=$(date '+%Y%m%d_%H%M%S_%N')
ALERT_FILE="/var/ossec/logs/alert_${DATESTAMP}.json"
echo "$INPUT_JSON" > "$ALERT_FILE"

# ✅ Optional: log raw input for debugging
DEBUG_DUMP="/var/ossec/logs/debug_input.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] --- INPUT_JSON from stdin ---" >> "$DEBUG_DUMP"
echo "$INPUT_JSON" >> "$DEBUG_DUMP"
echo "" >> "$DEBUG_DUMP"

# ✅ Main log file
LOG_FILE="/var/ossec/logs/active-response-script.log"
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "🔄 Captured alert JSON and saved to $ALERT_FILE"

# ✅ Check if alert file was saved correctly
if [ ! -s "$ALERT_FILE" ]; then
    log "❌ ALERT_FILE is empty! read from stdin may have failed."
    exit 1
fi

# ✅ Call your Python processor
#PYTHON_SCRIPT="/var/ossec/active-response/bin/SmartPT_AI_v1.py"
python3 "$PYTHON_SCRIPT" "$ALERT_FILE"
PY_EXIT_CODE=$?

if [ $PY_EXIT_CODE -ne 0 ]; then
    log "❌ Python failed with exit code $PY_EXIT_CODE"
else
    log "✅ Python completed successfully"
fi

# ❌ Don't delete the file (for inspection)
rm -f "$ALERT_FILE"
log "🧹 Kept alert file: $ALERT_FILE"

exit $PY_EXIT_CODE
