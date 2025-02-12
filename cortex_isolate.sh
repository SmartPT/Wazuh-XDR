read INPUT_JSON
echo $INPUT_JSON > /var/ossec/logs/data.json
python3 /var/ossec/active-response/bin/cortex/isolate.py

#notes 
The script cortex_isolate.sh is a simple Bash script used in the Wazuh active response framework. Here's a breakdown of its functionality:
read INPUT_JSON: This line reads JSON input from standard input and stores it in the variable INPUT_JSON.
echo $INPUT_JSON > /var/ossec/logs/networkviolation.json: The input JSON is written to a log file at /var/ossec/logs/networkviolation.json,  for logging or debugging purposes.
python3 /var/ossec/active-response/bin/cortex/isolate.py: Executes a Python script (isolate.py) responsible for handling isolation actions.
