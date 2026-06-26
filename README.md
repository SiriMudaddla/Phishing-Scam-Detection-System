# 🛡️ Ultimate Threat Intelligence Matrix

An enterprise-grade, localized incident response platform and forensic triage engine built to identify phishing payloads, social engineering vectors, and malicious infrastructure anomalies. 

This application combines real-time network layer queries, global registration lifespans, cryptographic handshake validation, and headless visual analysis—synthesizing them via **Gemini 2.5 Flash** for deep cognitive overrides and comprehensive verdicts.

---

## 🗂️ Project Directory Structure

```text
Phishing-Scam-Detection-System/
├── .streamlit/
│   └── config.toml             # Hardened local UI engine parameters & theme profiles
├── app.py                      # Main application pipeline, network modules, & vision logic
├── requirements.txt            # Explicit production framework dependency checklist
├── .gitignore                  # Active tracking filter (excludes databases and venv caches)
└── README.md                   # System documentation and deployment manual

```


## 🧰 Tech Stack & Languages Used

Languages: * 🐍 Python: Backend processing core, network socket bindings, and regex parsing.

🗃️ SQL (SQLite): Relational ledger state persistence for local triage history tracking.

Frameworks & Libraries:

1. Streamlit: Reactive security monitoring dashboard interface.

2. Google GenAI SDK: Modern high-volume token pipeline matching the gemini-2.5-flash core.

3. Playwright: Automated, isolated background browser orchestration (Chromium Sandbox).

4. Python-Whois: Direct global registry lookups via port 43 protocols.

5. Pillow & Standard Sockets (ssl, socket): Image payload handling and direct TCP connections for X.509 certificate validation.
'''

---

# ⚡ Local Quick-Start Guide


To deploy the application locally, follow the steps below.

## 1. Set Up Environment Variables

Configure your Google GenAI API key for the current PowerShell session.

```powershell

$env:GEMINI_API_KEY="YOUR_SECRET_API_KEY_HERE"
```

---

## 2. Install Dependencies

Install all required Python packages and Playwright browser binaries.

```powershell
# Install project dependencies
.\venv\Scripts\python.exe -m pip install -r requirements.txt --ignore-installed

# Install Chromium for Playwright
.\venv\Scripts\python.exe -m playwright install chromium
```

---

## 3. Launch the Application

Start the Streamlit application.

```powershell
.\venv\Scripts\python.exe -m streamlit run app.py
```

---

# 📑 Core Security Modules

### 📨 Forensic Email Analysis

Uses Google's Gemini model to analyze email content and identify phishing indicators, including:

* Urgency and fear-based language
* Authority impersonation
* Credential harvesting attempts
* Social engineering tactics
* Suspicious requests and malicious intent

---

### 🔗 Deep URL Metadata & Visual Analysis

The application performs multiple layers of URL inspection, including:

* Expands shortened URLs (e.g., `bit.ly`, `t.co`) to reveal their true destinations.
* Determines domain age using WHOIS registration records.
* Detects typosquatting and brand impersonation through heuristic matching.
* Evaluates SSL/TLS certificate issuer information and expiration dates.
* Captures a live webpage screenshot using an isolated Playwright browser.
* Uses visual analysis to identify fake login pages and phishing websites.

---

# 🔮 Future Roadmap

The current platform is fully functional for local phishing detection and security analysis. Planned enhancements include:

### 🖼️ Multimodal OCR Integration

Extract text directly from webpage screenshots to detect phishing content embedded within images.

### 🐳 Docker Sandboxing

Containerize the application using Docker to isolate browser execution and improve security.

### 🔐 Multi-Tenant Authentication

Implement Auth0 authentication, role-based access control, and IP rate limiting to support secure public deployments.

### 📧 Native `.EML` Email Parsing

Enable analysts to upload raw email files and automatically extract and validate:

* SPF
* DKIM
* DMARC
* Email headers
* Sender authentication results

---

## 🚀 Planned Enhancements

* OCR-powered phishing detection
* Docker-based secure execution
* Auth0 authentication and user management
* Advanced email forensic analysis
* Enhanced visual fraud detection
* Expanded threat intelligence integrations


---

# 👩‍💻 Author

**Siri Mudaddla**

* GitHub: `https://github.com/SiriMudaddla`
* LinkedIn: https://www.linkedin.com/in/siri-m-1baba1323/

---

# 🙏 Acknowledgements

This project utilizes several outstanding open-source technologies:

* Streamlit
  
* Google Gemini API
  
* Playwright
  
* SQLite
  
* Python

Special thanks to the open-source community for maintaining these tools.

---

# ⭐ Support

If you found this project useful:

* ⭐ Star this repository
  
* 🐛 Report issues
  
* 💡 Suggest new features
  
* 🍴 Fork the project and contribute

Your support helps improve the project for everyone.

