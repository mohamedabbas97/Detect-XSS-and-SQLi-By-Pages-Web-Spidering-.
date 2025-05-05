# Detect-XSS-and-SQLi-By-Pages-Web-Spidering-.
A tool for scanning for XSS and SQL Injection vulnerabilities in websites using Python and a Tkinter GUI. The tool crawls pages, detects forms, tests fields with a malicious payload, and generates detailed reports in PDF/JSON/TXT formats. It also supports optional login.

# Web Vulnerability Scanner (GUI-Based)

## 📌 Overview

A Python-based GUI application for scanning websites for **XSS (Cross-Site Scripting)** and **SQL Injection** vulnerabilities. The tool crawls pages, detects HTML forms, injects custom payloads, and reports potential vulnerabilities.

## 🎯 Features

* **Scan Types**: XSS or SQL Injection
* **Automatic Crawling**: Recursive scanning up to a configurable number of pages
* **Form Detection**: Finds and parses HTML forms
* **Payload Injection**: Tests fields with predefined or custom payloads
* **Optional Login**: Authenticate before scanning protected areas
* **GUI Interface**: Built with Tkinter for ease of use
* **Progress & Logs**: Live progress bar and real-time logging
* **Export Reports**: Save results as **PDF**, **JSON**, or **TXT**

## 🖥️ GUI Description

1. **Target URL**: Enter the base URL to scan.
2. **Tester Name**: Identify the tester for reports.
3. **Scan Type**: Choose between XSS or SQL Injection.
4. **Max Pages**: Limit the crawl depth.
5. **Start Scan**: Begin the crawling and scanning process.
6. **Save Report**: Export findings after completion.
7. **Status & Progress**: Monitor real-time status and progress bar.
8. **Logs Panel**: View detailed logs of each request and payload test.

## 🛠️ Technologies Used

* **Python 3.x**
* **Tkinter** for GUI
* **Requests** for HTTP interactions
* **BeautifulSoup** for HTML parsing
* **ReportLab** for PDF generation

## 📂 Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/your-username/web-vulnerability-scanner.git
   cd web-vulnerability-scanner
   ```
2. **Install dependencies**:

   ```bash
   pip install requests beautifulsoup4 reportlab
   ```
3. **Run the application**:

   ```bash
   python scanner.py
   ```

## 📖 Usage Instructions

1. Launch the application:

   ```bash
   python scanner.py
   ```
2. Fill in the required fields:

   * **Target URL**
   * **Tester Name**
   * **Scan Type** (XSS or SQL)
   * **Max Pages** to crawl
3. (Optional) Modify the `login_url` and `login_data` in code to scan authenticated pages.
4. Click **Start Scan** and wait for completion.
5. Click **Save Report** to export findings.

## 🧪 Sample Payloads

* **XSS**: `<img src=x onerror=alert('XSS')>`
* **SQLi**: `' OR '1'='1 -- -`

## 📋 Report Output Sample (PDF)

```
[VULN] https://target.com/form -> https://target.com/submit (POST)
  Payload: <img src=x onerror=alert('XSS')>

[FAIL] https://target.com/login -> https://target.com/login (POST)
  Payload: ' OR '1'='1 -- -
```

## 🔐 Optional Login Support

To scan restricted pages, update:

```python
login_url = "https://example.com/login"
login_data = {"username": "admin", "password": "admin"}
```

Pass these to the scanner initialization.

## ⚠️ Disclaimer

This tool is for **educational and authorized penetration testing** only. Do **not** use it against websites without explicit permission.

## ✒️ Author

Mohamed



