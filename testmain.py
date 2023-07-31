#!/usr/bin/python3 
  
import subprocess
import os
import time
import threading
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler('logs/test.log', maxBytes=20*1024*1024, backupCount=5)

# Create a formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Create a logger and add the handler to it
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

logging.info('Program started')

#subprocess.run(["python3", "test1.py"])
#subprocess.run(["python3", "test2.py"])
def run_script(path):
    subprocess.run(["python3", path])



# Create threads
thread1 = threading.Thread(target=run_script, args=("/opt/testcef/test1.py",))
thread2 = threading.Thread(target=run_script, args=("/opt/testcef/test2.py",))
thread3 = threading.Thread(target=run_script, args=("/opt/testcef/test3.py",))

logging.info('Program started')

# Start threads
thread1.start()
time.sleep(10)
thread2.start()
time.sleep(15)

thread3.start()
time.sleep(5)

# Wait for both threads to finish
thread1.join()
thread2.join()
thread3.join()

