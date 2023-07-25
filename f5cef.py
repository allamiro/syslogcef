#!/usr/bin/python3


# Import libararies 

import os
import pwd
import datetime
import logging
import grp
import re
from parsers import f5_syslog
import shutil
import time


# Set up logging
logging.basicConfig(
    filename='logs/f5-syslog-cef.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Log the start of the program
logging.info('Program started')

uid = pwd.getpwnam('root').pw_uid
gid = grp.getgrnam('root').gr_gid

patterns = {
    r"^<\d+>": f5_syslog,
}

# Function to process the logs
def syslog_to_cef(log):
    for pattern, function in patterns.items():
        if re.search(pattern, log):
            cef_log = function(log)
            if cef_log:
                logging.info(f"Log parsed by function {function.__name__}")  # Log the parsing
                return cef_log
            else:
                logging.error(f"No CEF conversion for log: {log}")
                return None
    logging.error(f"No match found for log: {log}")
    return None

# Directory with log files
logs_directory = '/opt/syslogcef/data/syslog/'
# Directory to store .processed files
processed_directory = '/opt/syslogcef/data/processed/'  # Replace this with the actual path

# Path to the .processed file
processed_file_path = os.path.join(processed_directory, 'processed_files.txt')

def file_already_processed(filename):
    # Check if the .processed file exists
    if not os.path.exists(processed_file_path):
        return False

    with open(processed_file_path, 'r', encoding='utf-8') as f:
        processed_files = f.read().splitlines()

    return filename in processed_files

def mark_file_as_processed(filename):
    with open(processed_file_path, 'a', encoding='utf-8') as f:
        f.write(filename + '\n')

# The script will run indefinitely
while True:
    # Iterate over all files in the directory
    for filename in os.listdir(logs_directory):
        # Check if the file is a log file and hasn't been processed yet
        if filename.endswith(".log") and not file_already_processed(filename):
            log_file_path = os.path.join(logs_directory, filename)
            with open(log_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            cef_logs = []
            for log_data in lines:
                cef_log = syslog_to_cef(log_data)
                if cef_log:
                    cef_logs.append(cef_log)
            if cef_logs:
                current_date = datetime.datetime.now()
                date_str = current_date.strftime("%Y-%m-%d-%H")
                cef_file_path = f'/opt/syslogcef/data/cef/{filename.rsplit(".", 1)[0]}_{date_str}.cef'
                with open(cef_file_path, 'w') as f:
                    f.write('\n'.join(cef_logs))
                # os.chown(cef_file_path, uid, gid)  # You need to define uid and gid                                                                                                                                                                                          69,17         84%
            # Mark the file as processed
            mark_file_as_processed(filename)
    # Wait for a while before the next iteration to prevent high CPU usage
    time.sleep(3600)  # Wait for 1 second