# Sensitive Data Hunter

A lightweight Static Application Security Testing (SAST) tool written in Python. It recursively scans directory trees to identify potential data leaks, specifically targeting hardcoded credentials and exposed email addresses in source code and configuration files.

## 🚀 Features

* **Recursive Scanning:** Deeply scans nested directories using `os.walk`.
* **Pattern Recognition:** Uses compiled Regex with capture groups to identify:
* **Standard Emails:** `user@domain.com`
* **Hardcoded Passwords:** Variable assignments like `db_password = "secret"` or JSON keys `"password": "123"`.


* **Smart Filtering:** Automatically ignores binary files (images, executables) and focuses on text-based extensions (`.py`, `.txt`, `.json`, `.env`, etc.).
* **Robust Error Handling:** Features `errors='ignore'` encoding handling to prevent crashes on corrupted files or mixed-encoding environments.

## 🛠️ Installation

No external dependencies are required. This script runs on standard Python 3.

```bash
git clone https://github.com/Ade20boss/SecretHunter.git
cd SecretHunter

```

## 📖 Usage

1. Run the script:
```bash
python sensitive_data_hunter.py

```


2. Enter the absolute path to the directory you want to audit.

### Example Output

```text
Scanning directory....
Directory scanned successfully.

Opening Files and reading lines...

[ALERT: EMAIL] Found in contact.txt (Line 4)
    Line: Please forward billing to admin@startup.io
    Email found: admin@startup.io
------------------------------
[ALERT: PASSWORD] Found in config.py (Line 12)
   LEAKED PASSWORD: "SuperSecretKey123!"
------------------------------

Operation completed successfully.

```

## 🧠 How It Works

1. **Validation:** Verifies the target directory exists and is accessible.
2. **File Walker:** Iterates through every file in the tree.
3. **Extension Filter:** Checks if the file matches a whitelist of text extensions (`.txt`, `.py`, `.json`, etc.) to optimize performance.
4. **Content Analysis:**
* Reads the file line-by-line using `enumerate()` to track location.
* Applies Regex logic to detect patterns.
* **Password Regex Logic:** `[\w\"]*password[\w\"]*\s*[:=]\s*['\"](.*?)['\"]`
* Catches `password = "x"`, `db_password = "x"`, and `"password": "x"`.
* Uses a capture group to extract only the secret value inside the quotes.





## ⚠️ Disclaimer

This tool is intended for **educational and defensive purposes only**. Use it to audit your own code or directories you have permission to scan.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

