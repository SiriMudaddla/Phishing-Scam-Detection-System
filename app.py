import streamlit as st
import os
import re
import socket
import ssl
import whois
import sqlite3
import requests
from datetime import datetime
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright
from google import genai
from google.genai import types
from PIL import Image

# --- DATABASE LAYER ---
DB_FILE = "security_triage.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS triage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            scan_type TEXT,
            target_input TEXT,
            verdict TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_to_db(scan_type, target_input, verdict):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO triage_logs (timestamp, scan_type, target_input, verdict) VALUES (?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_type, target_input, str(verdict))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database logging failure: {e}")

init_db()

# --- AI CLIENT ---
try:
    client = genai.Client()
except Exception as e:
    st.error(f"Failed to initialize Gemini Client. Ensure GEMINI_API_KEY is set. Error: {e}")
    st.stop()

st.set_page_config(page_title="Ultimate Threat Intelligence Matrix", page_icon="🛡️", layout="centered")

st.markdown(
    """
    <style>
    .centered-title { text-align: center; font-weight: bold; margin-bottom: 5px; }
    .centered-subtitle { text-align: center; color: #666; margin-bottom: 30px; }
    .centered-header { text-align: center; margin-top: 25px; margin-bottom: 15px; }
    .metric-box { padding: 12px; border-radius: 6px; background-color: #f1f3f6; margin-bottom: 12px; border-left: 5px solid #1E88E5; color: #111111; }
    .danger-box { padding: 12px; border-radius: 6px; background-color: #fde8e8; margin-bottom: 12px; border-left: 5px solid #E53935; color: #9B1C1C; }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("<h1 class='centered-title'>🛡️ Ultimate Threat Intelligence Matrix</h1>", unsafe_allow_html=True)
st.markdown("<p class='centered-subtitle'>All Advanced Layers: Sockets, WHOIS, Database Caching, and Visual Analysis</p>", unsafe_allow_html=True)

# --- SIDEBAR DATABASE VIEW ---
st.sidebar.title("📊 Triage History")

if st.sidebar.button("Clear Session / Refresh Dashboard"):
    st.rerun()

try:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, target_input, verdict FROM triage_logs ORDER BY id DESC LIMIT 10")
    recent_scans = cursor.fetchall()
    conn.close()
    if recent_scans:
        for scan in recent_scans:
            st.sidebar.caption(f"⏱️ {scan[0]}")
            st.sidebar.markdown(f"**Target:**\n`{scan[1]}`")
            st.sidebar.markdown(f"**Diagnosis:**\n{scan[2]}")
            st.sidebar.markdown("---")
    else:
        st.sidebar.info("No historical entries registered yet.")
except Exception as e:
    st.sidebar.error(f"Could not read database: {e}")

analysis_type = st.radio("Select Security Module:", ("Forensic Email Check", "Deep URL Metadata & Visual Scan"))

# --- NETWORK UTILITIES ---

def expand_and_trace_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        response = requests.request("HEAD", url, allow_redirects=True, timeout=4)
        return response.url, None
    except Exception as e:
        return url, f"Routing trace connection drop notice: {str(e)}"

def capture_page_screenshot(url, output_path="page_snapshot.png"):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(7000)
            page.goto(url)
            page.screenshot(path=output_path)
            browser.close()
        return output_path, None
    except Exception as e:
        return None, f"Visual capture skipped: {str(e)}"

def get_whois_metadata(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            days_old = (datetime.now() - creation_date).days
            if days_old < 30:
                return f"🚨 BRAND NEW DOMAIN: Registered only {days_old} days ago!", True
            return f"✅ Established Domain: Registered {days_old} days ago.", False
        return "⚠️ Domain metadata obscured.", False
    except Exception:
        return "❌ Identity Flag: Unregistered domain or lookup blocked by registry.", True

def analyze_ssl_certificate(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get('notAfter')
                expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                days_to_expire = (expiry_date - datetime.now()).days
                issuer = dict(x[0] for x in cert.get('issuer'))
                issuer_name = issuer.get('commonName', 'Unknown CA')
                return f"🔒 Valid SSL Connection (Issued by: {issuer_name}). Expires in {days_to_expire} days.", None
    except Exception as e:
        return "🔓 INSECURE: Port 443 TLS handshake failed.", str(e)

def extract_url_heuristics(url):
    flags = []
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    suspicious_tlds = ['.xyz', '.top', '.club', '.support', '.info', '.biz', '.cc', '.icu', '.work']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        flags.append("Suspicious Domain Class: Uses a high-risk cheap extension.")
    brand_keywords = ['paypal', 'bank', 'netflix', 'amazon', 'google', 'apple', 'microsoft', 'secure', 'login', 'verify']
    for keyword in brand_keywords:
        if keyword in domain and not (domain.endswith(f"{keyword}.com") or domain.endswith(f"{keyword}.org")):
            flags.append(f"Identity Masking: Subdomain contains word '{keyword}' outside core domain.")
    if "@" in domain:
        flags.append("Malicious Structuring: Inline authentication mask detected.")
    return flags, domain

# --- INTERACTION LAYERS ---

system_instruction = (
    "You are an elite automated incident responder. Analyze the provided network logs, "
    "heuristics, and any accompanying visual screenshot. Provide a clear diagnosis: SECURE, SUSPICIOUS, or MALICIOUS. "
    "Explain all anomalies, logo abuse, or text discrepancies clearly."
)

if analysis_type == "Forensic Email Check":
    user_input = st.text_area("Paste Content Here:", height=220, placeholder="Urgent message content...")
    if st.button("Execute Core Threat Run", type="primary"):
        if not user_input.strip():
            st.warning("Please input arguments.")
        else:
            with st.spinner("Decoding NLP metrics..."):
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=f"Analyze this text for phishing vulnerabilities:\n\n{user_input}",
                    config=types.GenerateContentConfig(system_instruction=system_instruction)
                )
                st.markdown("<h3 class='centered-header'>AI Analysis Verdict</h3>", unsafe_allow_html=True)
                st.write(response.text)
                log_to_db("Text Scan", user_input, response.text)

else:
    user_input = st.text_input("Input Target Link:", placeholder="Example: bit.ly/3xYz7 or update-paypal-account.support")
    if st.button("Execute Advanced Structural & Visual Check", type="primary"):
        if not user_input.strip():
            st.warning("No tracking link provided.")
        else:
            with st.spinner("Tracing routing layers..."):
                final_url, trace_error = expand_and_trace_url(user_input)
            
            heuristics, clean_domain = extract_url_heuristics(final_url)
            
            with st.spinner("Analyzing SSL certificates and WHOIS lifespans..."):
                whois_status, whois_critical = get_whois_metadata(clean_domain)
                ssl_status, ssl_error = analyze_ssl_certificate(clean_domain)
            
            with st.spinner("Launching isolated browser sandbox to capture page layout..."):
                img_path, screenshot_error = capture_page_screenshot(final_url)
            
            st.markdown("<h3 class='centered-header'>Hardware Infrastructure Logs</h3>", unsafe_allow_html=True)
            if final_url != user_input:
                st.info(f"🔄 **Redirect Traced:** `{final_url}`")
                
            st.markdown(f"<div class='metric-box'>🛡️ <b>Domain Lifespan:</b> {whois_status}</div>", unsafe_allow_html=True)
            if ssl_error:
                st.markdown(f"<div class='danger-box'>🔓 <b>SSL Warning:</b> {ssl_status} ({ssl_error})</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"<div class='metric-box'>🔒 <b>Encryption Validation:</b> {ssl_status}</div>", unsafe_allow_html=True)
                
            if heuristics:
                st.error("🚨 Heuristic Static Rule Flags Match:")
                for flag in heuristics:
                    st.write(f"- {flag}")
            
            if img_path and os.path.exists(img_path):
                st.markdown("**Captured Sandbox View:**")
                st.image(img_path, caption="Automated Headless Browser Capture Image", use_container_width=True)
            
            with st.spinner("Synthesizing parameters and vision data into AI core..."):
                ai_prompt = f"""
                Analyze this operational network profile and accompanying visual layout structure:
                - Target Input URL: {user_input}
                - Final Absolute Destination: {final_url}
                - Domain Under Analysis: {clean_domain}
                - WHOIS Registration Profile: {whois_status}
                - SSL Cryptographic State: {ssl_status}
                - Heuristic Static Anomalies: {', '.join(heuristics) if heuristics else 'None'}
                - Screenshot Status Notice: {screenshot_error if screenshot_error else 'Image Attached successfully.'}
                """
                
                try:
                    contents_payload = [ai_prompt]
                    if img_path and os.path.exists(img_path):
                        contents_payload.append(Image.open(img_path))
                    
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=contents_payload,
                        config=types.GenerateContentConfig(system_instruction=system_instruction)
                    )
                    
                    st.markdown("<h3 class='centered-header'>AI Multimodal Intelligence Verdict</h3>", unsafe_allow_html=True)
                    st.write(response.text)
                    
                    log_to_db("Visual Matrix", final_url, response.text)
                except Exception as e:
                    st.error(f"Threat generation blueprint failure: {e}")

st.markdown("---")
st.caption("Ultimate Tier Blueprint Engine. Running active multimodal pipeline validation configurations.")
