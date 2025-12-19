"""
Sensitive Data Hunter
---------------------
A Static Application Security Testing (SAST) script.
This tool recursively scans a directory structure to detect potential security leaks,
specifically identifying:
1. Exposed Email Addresses
2. Hardcoded Passwords (e.g., password = "secret")
3. Hardcoded API Keys (e.g., api_key = "12345")

Author: KernelGhost


It is designed to be robust against encoding errors and binary files.
"""

import os
import re
import time

def data_hunter(directory):
    # Initialize a counter to track the total number of security issues found
    hits = 0

    # --- REGEX PATTERN DEFINITIONS ---
    # 1. Email Regex:
    #    [a-zA-Z0-9._%+-]+  -> Matches the username part (alphanumeric + symbols)
    #    @                  -> Matches the literal '@' symbol
    #    [a-zA-Z0-9.-]+     -> Matches the domain name
    #    \.[a-zA-Z]{2,4}    -> Matches the extension (like .com, .net) length 2-4
    email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}")

    # 2. Password Regex:
    #    [\w\"]*password[\w\"]* -> Matches "password", "db_password", "PASSWORD", or "password" inside quotes
    #    \s*[:=]\s* -> Matches zero or more spaces followed by ':' or '=' (covers JSON & Python style)
    #    ['\"](.*?)['\"]        -> CAPTURE GROUP: Matches any character inside single or double quotes. 
    #                              This captures the actual secret value.
    sensitive_data_regex = re.compile(r"([\w\"]*password[\w\"]|password)*\s*[:=]\s*['\"](.*?)['\"]", re.IGNORECASE)
    api_key_regex = re.compile(r"api[_-]?key\s*[:=]\s*['\"](.*?)['\"]", re.IGNORECASE)

    print("\nScanning directory....")
    time.sleep(1) # Small pause for user experience (UX)

    # --- VALIDATION PHASE ---
    # We attempt to list the directory first using the "Easier to Ask Forgiveness than Permission" (EAFP) principle.
    # This catches errors early before we start the heavy lifting of walking the tree.
    try:
        directory_entries = os.listdir(directory)
    except FileNotFoundError:
        # Handles case where the user typed a path that doesn't exist
        print(f"Error: The directory '{directory}' was not found.")
        exit()
    except NotADirectoryError:
        # Handles case where the user pointed to a file (e.g., script.py) instead of a folder
        print(f"Error: '{directory}' is a file, not a directory.")
        exit()
    except PermissionError:
        # Handles case where the OS denies access to the folder
        print(f"Error: You do not have permission to access '{directory}'.")
        exit() 
    print("Directory scanned successfully.")
    
    # --- TRAVERSAL PHASE ---
    # os.walk is a generator that recursively yields the directory tree.
    # It allows us to go deep into sub-folders automatically.
    directory_entries = os.walk(directory)
    
    print("\nOpening Files and reading lines in each file.......")
    print("This might take some time")
    time.sleep(1)

    for root, dirs, files in directory_entries:
        for file in files:
            # Construct the absolute path to the file
            file_path = os.path.join(root, file)

            # --- FILTERING ---
            # Optimization: We check the file extension before opening it.
            # We only want to scan text-based files. Opening binary files (like images, .exe, .zip)
            # is a waste of CPU and can cause read errors.
            if not file.lower().endswith(('.txt', '.py', '.log', '.json', '.md', '.csv', '.xml', '.env')):
                continue

            try:
                # --- FILE READING ---
                # errors="ignore": This is CRITICAL. 
                # If a file contains non-UTF-8 characters (like a corrupted bit), 
                # default Python behavior is to crash. "ignore" tells Python to drop the bad byte and keep going.
                with open(file_path, "r", encoding="utf-8", errors="ignore") as file_handler:
                    
                    # enumerate(file_handler, 1):
                    # Reads the file line-by-line efficiently without loading the whole file into RAM.
                    # The '1' tells Python to start counting line numbers at 1 (instead of 0).
                    for line_num, line in enumerate(file_handler, 1):
                        
                        # Remove leading/trailing whitespace (spaces, tabs, newlines) for cleaner matching
                        line = line.strip()

                        # --- PATTERN MATCHING ---
                        # .search() scans the entire string for the pattern (unlike .match() which only checks the start)
                        match_email = email_regex.search(line)
                        match_sensitive = sensitive_data_regex.search(line)
                        match_api_key = api_key_regex.search(line)

                        # If an email is found, print alert details
                        if match_email:
                            print(f"[ALERT: EMAIL] Found in {file} (Line {line_num})")
                            print(f"    Line: {line}")
                            # .group() retrieves the specific part of the string that matched the regex
                            print(f"Email found: {match_email.group()}")
                            print("-" * 30)
                            hits += 1
                        
                        # If a password assignment is found, print alert details
                        if match_sensitive:
                            print(f"[ALERT: PASSWORD] Found in {file} (Line {line_num})")
                            print(f"   LEAKED PASSWORD: {match_sensitive.group()}") 
                            print("-" * 30)
                            hits += 1
                        
                        # If an API key is found, print alert details   
                        if match_api_key:
                            print(f"[ALERT: API KEY] Found in {file} (Line {line_num})")
                            print(f"   LEAKED API_KEY: {match_api_key.group()}") 
                            print("-" * 30)
                            hits += 1
                
            # --- ERROR HANDLING ---
            # If a specific file is locked or unreadable (PermissionError during open),
            # we catch the exception and CONTINUE to the next file so the scan doesn't stop.
            except Exception as e:
                print(f"[ERROR] Could not read file: {file}, due to {e}")
                continue

    print("Operation completed succcessfully")
    print("Total issues found so far:", hits)

if __name__ == "__main__":
    # Entry point: Prompts user for input when run directly
    data_hunter(input("Enter directory path here: "))