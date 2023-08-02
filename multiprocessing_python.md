```
from multiprocessing import Process
import subprocess

def run_script(path_to_script):
    # Using the python interpreter to run the script
    subprocess.call(["python", path_to_script])

if __name__ == '__main__':
    # List of paths to your scripts
    scripts = ["/path_to_directory1/script1.py", 
               "/path_to_directory2/script2.py", 
               "/path_to_directory3/script3.py"]

    # Create a list to keep all processes
    processes = []

    # Create processes
    for script in scripts:
        proc = Process(target=run_script, args=(script,))
        processes.append(proc)

    # Start processes
    for proc in processes:
        proc.start()

    # Ensure all processes have finished execution
    for proc in processes:
        proc.join()
```
