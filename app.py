# app.py
import os
import io
import tempfile
import streamlit as st
import requests
import whois
import base64
import re
import socket
from textblob import TextBlob
from fpdf import FPDF
from datetime import datetime, timezone
import plotly.express as px
import plotly.graph_objs as go
import matplotlib.pyplot as plt
from dateutil import parser as dateparser

# Optional OpenAI - used only if OPENAI_API_KEY set in env
try:
    import openai
except Exception:
    openai = None

# ---------------------------
# CONFIG - place your API KEYS here (or set as env vars)
# ---------------------------
VT_API_KEY = os.getenv("VT_API_KEY", )
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", )
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY",)  # set this if you want LLM summaries

if OPENAI_API_KEY and openai:
    openai.api_key = OPENAI_API_KEY

VT_BASE = "https://www.virustotal.com/api/v3"

# ---------------------------
# Helpers (VirusTotal, WHOIS, AbuseIPDB, analysis)
# ---------------------------

def encode_url_for_vt(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def vt_get_url_analysis(url):
    headers = {"x-apikey": VT_API_KEY}
    url_id = encode_url_for_vt(url)
    resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
    if resp.status_code == 200:
        return resp.json()
    else:
        post_resp = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
        if post_resp.status_code in (200, 201):
            try:
                entity_id = post_resp.json()["data"]["id"]
                for _ in range(5):
                    get_resp = requests.get(f"{VT_BASE}/analyses/{entity_id}", headers=headers)
                    if get_resp.status_code == 200:
                        return get_resp.json()
                return post_resp.json()
            except Exception:
                return post_resp.json()
        else:
            return {"error": f"VirusTotal error {post_resp.status_code}"}

def vt_parse_stats(resp_json):
    try:
        if resp_json.get("data") and resp_json["data"].get("attributes") and resp_json["data"]["attributes"].get("last_analysis_stats"):
            return resp_json["data"]["attributes"]["last_analysis_stats"]
        # fallback: return what we can
        return resp_json
    except Exception:
        return {"error": "Unable to parse VirusTotal response"}

def extract_domain(url):
    match = re.search(r"https?://([^/]+)", url)
    if match:
        return match.group(1).split(':')[0]
    return url

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "status": w.status
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def check_abuseipdb(ip):
    if not ABUSE_API_KEY:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", {})
        else:
            return {"error": f"AbuseIPDB error {r.status_code}"}
    except Exception as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

def extract_links(text):
    return re.findall(r'(https?://\S+)', text)

def analyze_email(text):
    keywords = ['urgent', 'immediately', 'click', 'password', 'login', 'verify', 'account']
    score, reasons = 0, []
    txt = text.lower()
    for kw in keywords:
        if kw in txt:
            score += 15
            reasons.append(f"Found keyword: '{kw}'")
    links = extract_links(text)
    if links:
        score += min(30, 10*len(links))
        reasons.append(f"Found {len(links)} link(s)")
    try:
        if TextBlob(text).sentiment.polarity < -0.1:
            score += 10
            reasons.append("Negative sentiment detected")
    except:
        pass
    score = min(score, 100)
    return {"score": score, "reasons": reasons, "links": links}

def color_code_url(stats):
    try:
        if isinstance(stats, dict) and stats.get("malicious", 0) > 0:
            return "red"
        elif isinstance(stats, dict) and stats.get("suspicious", 0) > 0:
            return "orange"
        else:
            return "green"
    except:
        return "gray"

def color_code_email(score):
    if score>70: return "red"
    elif score>40: return "orange"
    else: return "green"

# ---------------------------
# New helpers: domain age, threat score, LLM summary, plotting, PDF images
# ---------------------------

def get_domain_age_days(whois_info):
    try:
        cd = whois_info.get("creation_date")
        if not cd:
            return None
        # cd may be list or datetime or str
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, str):
            cd = dateparser.parse(cd)
        # if datetime with tz info -> convert to UTC naive
        if hasattr(cd, "tzinfo") and cd.tzinfo is not None:
            cd = cd.astimezone(timezone.utc).replace(tzinfo=None)
        delta = datetime.utcnow() - cd
        return max(0, delta.days)
    except Exception:
        return None

def compute_threat_score(vt_stats, abuse_data, domain_age_days):
    # vt component: fraction of malicious engines (0-100)
    vt_component = 0
    if isinstance(vt_stats, dict):
        total = 0
        for k in ["harmless","malicious","suspicious","undetected","timeout"]:
            total += int(vt_stats.get(k,0))
        if total > 0:
            vt_component = (int(vt_stats.get("malicious",0)) / total) * 100
    # abuse component: abuseConfidenceScore (0-100) if available
    abuse_component = 0
    if isinstance(abuse_data, dict) and abuse_data.get("abuseConfidenceScore") is not None:
        try:
            abuse_component = int(abuse_data.get("abuseConfidenceScore", 0))
        except:
            abuse_component = 0
    # domain risk: new domains = higher risk
    if domain_age_days is None:
        domain_risk = 30  # unknown => moderate
    else:
        if domain_age_days < 30:
            domain_risk = 100
        elif domain_age_days < 365:
            domain_risk = 60
        else:
            domain_risk = 0
    # weighted sum: vt 50%, abuse 30%, domain 20%
    score = 0.5*vt_component + 0.3*abuse_component + 0.2*domain_risk
    return int(round(min(max(score, 0), 100)))

# LLM summary: uses OpenAI if OPENAI_API_KEY is set, else fallback deterministic summary
def llm_summary(domain, vt_stats, abuse_data, domain_age_days, threat_score):
    # structured prompt content
    vt_text = ""
    if isinstance(vt_stats, dict):
        vt_text = ", ".join([f"{k}: {v}" for k,v in vt_stats.items()])
    abuse_text = ""
    if isinstance(abuse_data, dict):
        # show main fields if present
        abuse_text = f"abuseConfidenceScore: {abuse_data.get('abuseConfidenceScore', 'N/A')}, totalReports: {abuse_data.get('totalReports', 'N/A')}, country: {abuse_data.get('countryCode', 'N/A')}"
    domain_age_text = f"{domain_age_days} days old" if domain_age_days is not None else "unknown age"
    prompt = (
        f"Domain: {domain}\n"
        f"VirusTotal stats: {vt_text}\n"
        f"AbuseIPDB: {abuse_text}\n"
        f"Domain age: {domain_age_text}\n"
        f"Computed threat score (0-100): {threat_score}\n\n"
        "Produce two short (2-3 sentence) summaries:\n"
        "1) A technical summary for a SOC analyst.\n"
        "2) A non-technical plain-language summary for a manager/customer.\n"
        "Keep them concise and actionable."
    )
    # If OpenAI available and key set, call it
    if OPENAI_API_KEY and openai:
        try:
            resp = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role":"system","content":"You are a helpful cybersecurity assistant."},
                          {"role":"user","content":prompt}],
                temperature=0.2,
                max_tokens=250
            )
            text = resp["choices"][0]["message"]["content"].strip()
            # We assume the model returns both summaries; return text as-is and duplicate for both fields for simplicity
            # Try to split into two parts if possible
            parts = text.split("\n\n", 1)
            technical = parts[0].strip() if parts else text
            nontech = parts[1].strip() if len(parts)>1 else text
            return {"technical": technical, "nontechnical": nontech}
        except Exception as e:
            # fallback to deterministic
            pass

    # Fallback deterministic summary generator
    # Technical
    tech = f"Technical Summary: Threat score {threat_score}/100. VT: {vt_text or 'N/A'}. AbuseIPDB: {abuse_text or 'N/A'}. Domain age: {domain_age_text}."
    # Non-technical
    nontech = "Non-Technical Summary: " 
    if threat_score > 70:
        nontech += "High risk — this domain/IP shows multiple red flags and should be blocked or investigated further."
    elif threat_score > 40:
        nontech += "Medium risk — proceed with caution and monitor activity."
    else:
        nontech += "Low risk — no immediate action required, but continue normal monitoring."
    return {"technical": tech, "nontechnical": nontech}

# Plotly interactive charts for dashboard (returns plotly figures)
def make_vt_pie(vt_stats):
    # Accept missing / fallback
    if not isinstance(vt_stats, dict):
        return None
    labels = []
    values = []
    for k in ["malicious","suspicious","undetected","harmless","timeout"]:
        val = int(vt_stats.get(k,0))
        if val > 0:
            labels.append(k)
            values.append(val)
    if not labels:
        labels = ["unknown"]
        values = [1]
    fig = px.pie(values=values, names=labels, title="VirusTotal Analysis")
    return fig

def make_threat_gauge(score):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = score,
        gauge = {'axis': {'range': [0,100]},
                 'bar': {'color': "darkred" if score>70 else ("orange" if score>40 else "green")},
                 'steps': [
                     {'range':[0,40],'color':"#d4f4dd"},
                     {'range':[40,70],'color':"#fff3cd"},
                     {'range':[70,100],'color':"#f8d7da"}
                 ]},
        title = {'text': "Overall Threat Score"}
    ))
    fig.update_layout(height=300)
    return fig

# Matplotlib images for PDF (returns PNG bytes)
def pie_image_bytes(vt_stats):
    fig, ax = plt.subplots(figsize=(4,3))
    labels = []
    values = []
    for k in ["malicious","suspicious","undetected","harmless","timeout"]:
        val = int(vt_stats.get(k,0)) if isinstance(vt_stats, dict) else 0
        if val > 0:
            labels.append(k)
            values.append(val)
    if not labels:
        labels = ["unknown"]
        values = [1]
    ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf.read()

def gauge_image_bytes(score):
    fig, ax = plt.subplots(figsize=(4,1.2))
    ax.barh([0], [score], color=("darkred" if score>70 else ("orange" if score>40 else "green")))
    ax.set_xlim(0,100)
    ax.set_yticks([])
    ax.set_xlabel(f"Threat Score: {score}/100")
    buf = io.BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf.read()

def generate_pdf_with_images(summary_dict, image_bytes_list=None, filename="PhishReport.pdf"):
    pdf = FPDF()
    pdf.add_page()
    
    # Add a Unicode font (use a TTF file in your project folder)
    # Download a free Unicode font like DejaVuSans.ttf or NotoSans-Regular.ttf
    font_path = "Noto_Sans/static/NotoSans-Regular.ttf"  # put this TTF in your project folder
    # Add the font
    pdf.add_font("NotoSans", "", "NotoSans-Regular.ttf", uni=True)
    pdf.add_font("NotoSans", "B", "NotoSans-Bold.ttf", uni=True)

# Use it
    pdf.set_font("NotoSans", "B", 14)  # for heading
    pdf.cell(0, 10, "PhishIntelli - Threat Report", ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("NotoSans", "", 11)   # for normal text

    
    for k, v in summary_dict.items():
        text = str(v)
        pdf.multi_cell(0, 7, f"{k}: {text}")
        pdf.ln(1)
    
    # Add images
    if image_bytes_list:
        for img_bytes in image_bytes_list:
            tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            tmp.write(img_bytes)
            tmp.flush()
            tmp.close()
            try:
                pdf.image(tmp.name, w=180)
                pdf.ln(4)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmp.name)
                except:
                    pass
    
    tmp_out = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp_out.close()
    pdf.output(tmp_out.name)
    with open(tmp_out.name, "rb") as f:
        data = f.read()
    try:
        os.unlink(tmp_out.name)
    except:
        pass
    return data

# ---------------------------
# Streamlit UI
# ---------------------------
st.set_page_config(page_title="PhishIntelli", layout="wide")
st.title("PhishIntelli - AI Threat Intelligence Dashboard")

# Sidebar demo input (kept)
with st.sidebar:
    st.header("Demo")
    demo_url = st.selectbox("Demo URLs", [
        "https://www.google.com",
        "http://malicious.test",
        "http://chinacxyy.com/piccodejs-000.asp?lm2=191&x=3&y=2&w=90&h=63&open=1&n=10&tj=0"
    ])
    demo_email = st.selectbox("Demo Emails", [
        "Your account has been locked! Click https://example.com to verify.",
        "Hello Rahul, your parcel is shipped. Track here: https://shopsafe.example"
        '''Subject: URGENT: Your account has been locked — Verify now

        Hello,

        We detected suspicious activity on your account and temporarily locked it. To restore access immediately, click the link below and verify your credentials within 24 hours. Failure to do so will permanently close your account.

        https://example.com/verify-login

        Username: john.doe@example.com

        Sincerely,
        Customer Support
        '''
    ])
    st.markdown("---")
    st.write("LLM summary status:")
    if OPENAI_API_KEY and openai:
        st.success("OpenAI available for summaries")
    else:
        st.info("Using fallback deterministic summary (no OpenAI key)")

mode = st.radio("Analyze:", ("URL","Email/Text"))

# ---------- URL mode ----------
if mode == "URL":
    url_input = st.text_input("Enter URL", value=demo_url)
    if st.button("Scan URL"):
        if not url_input or "http" not in url_input:
            st.warning("Please enter a valid URL starting with http:// or https://")
        else:
            with st.spinner("Running checks..."):
                vt_resp = vt_get_url_analysis(url_input)
                vt_stats = vt_parse_stats(vt_resp)
                st.subheader("VirusTotal")
                st.json(vt_stats)
                color = color_code_url(vt_stats)
                st.markdown(f"**Quick verdict:** <span style='color:{color};font-weight:700'>{'Malicious' if color=='red' else ('Suspicious' if color=='orange' else 'Likely Safe')}</span>", unsafe_allow_html=True)

                # WHOIS
                domain = extract_domain(url_input)
                whois_info = get_whois(domain)
                st.subheader("WHOIS")
                st.write("Domain:", domain)
                st.json(whois_info)

                # domain age
                domain_age_days = None
                try:
                    domain_age_days = get_domain_age_days(whois_info)
                    st.write("Domain age (days):", domain_age_days if domain_age_days is not None else "Unknown")
                except:
                    st.write("Domain age: Unknown")

                # Resolve IP
                ip = resolve_ip(domain)
                st.subheader("DNS / IP")
                st.write("Resolved IP:", ip if ip else "Could not resolve IP")

                # AbuseIPDB
                abuse_data = None
                if ip:
                    abuse_data = check_abuseipdb(ip)
                    if abuse_data is None:
                        st.info("AbuseIPDB check skipped (no API key configured).")
                    elif isinstance(abuse_data, dict) and abuse_data.get("error"):
                        st.warning(f"AbuseIPDB: {abuse_data.get('error')}")
                    else:
                        st.subheader("AbuseIPDB")
                        st.json(abuse_data)
                        score = abuse_data.get("abuseConfidenceScore", 0)
                        if score > 50:
                            st.error(f"High risk IP — Score: {score}")
                        elif score > 10:
                            st.warning(f"Medium risk IP — Score: {score}")
                        else:
                            st.success(f"Low risk IP — Score: {score}")

                # Threat score
                threat_score = compute_threat_score(vt_stats, abuse_data, domain_age_days)
                st.subheader("Overall Threat Score")
                fig_gauge = make_threat_gauge(threat_score)
                st.plotly_chart(fig_gauge, use_container_width=True)

                # VT pie chart
                fig_pie = make_vt_pie(vt_stats)
                if fig_pie:
                    st.plotly_chart(fig_pie, use_container_width=True)

                # LLM summary (technical + non-technical)
                summary_map = llm_summary(domain, vt_stats, abuse_data, domain_age_days, threat_score)
                st.subheader("AI Summary (Technical)")
                st.write(summary_map.get("technical"))
                st.subheader("AI Summary (Non-Technical)")
                st.write(summary_map.get("nontechnical"))

                # PDF generation with chart images
                pie_img = pie_image_bytes(vt_stats)
                gauge_img = gauge_image_bytes(threat_score)
                summary_for_pdf = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "url": url_input,
                    "domain": domain,
                    "resolved_ip": ip,
                    "threat_score": threat_score,
                    "llm_summary_technical": summary_map.get("technical"),
                    "llm_summary_nontechnical": summary_map.get("nontechnical"),
                    "whois": whois_info
                }
                pdf_bytes = generate_pdf_with_images(summary_for_pdf, image_bytes_list=[pie_img, gauge_img])
                st.download_button("Download PDF Report", data=pdf_bytes, file_name="PhishIntelli_Report.pdf", mime="application/pdf")

# ---------- Email/Text mode ----------
else:
    email_text = st.text_area("Paste email/text", value=demo_email, height=220)
    if st.button("Analyze Email"):
        if not email_text or len(email_text.strip()) < 5:
            st.warning("Please provide some text to analyze.")
        else:
            result = analyze_email(email_text)
            color = color_code_email(result["score"])
            label = "Likely Safe" if color == "green" else ("Suspicious" if color == "orange" else "High Risk")
            st.markdown(f"### Suspicious Score: <span style='color:{color}'>{result['score']}/100 — {label}</span>", unsafe_allow_html=True)
            st.write("**Reasons / Signals detected:**")
            if result["reasons"]:
                for r in result["reasons"]:
                    st.write("- " + r)
            else:
                st.write("No strong suspicious keywords detected.")
            st.write("**Extracted link(s):**")
            if result["links"]:
                for link in result["links"]:
                    st.write("-", link)
            else:
                st.write("No links detected.")

            # LLM summary for email
            email_summary = llm_summary("N/A (email)", {}, None, None, result["score"])
            st.subheader("AI Summary (Non-Technical)")
            st.write(email_summary.get("nontechnical"))

            # create simple chart for email (score gauge) and pdf
            pie_img = None
            gauge_img = gauge_image_bytes(result["score"])
            summary_for_pdf = {
                "timestamp": datetime.utcnow().isoformat(),
                "text_excerpt": email_text[:500].replace("\n", " "),
                "score": result["score"],
                "reasons": result["reasons"],
                "links": result["links"],
                "llm_summary": email_summary.get("nontechnical")
            }
            pdf_bytes = generate_pdf_with_images(summary_for_pdf, image_bytes_list=[gauge_img])
            st.download_button("Download PDF Report", data=pdf_bytes, file_name="PhishIntelli_Email_Report.pdf", mime="application/pdf")
