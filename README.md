# PhishIntelli
AI-powered tool to analyze URLs and emails for phishing threats, compute threat scores, generate summaries, and produce PDF reports.
Overview:
---------
PhishIntelli is a cybersecurity tool that analyzes URLs and emails to detect phishing threats. 
It computes a threat score, visualizes results using charts, and generates PDF reports.

Requirements:
-------------
- Python 3.11+
- pip install -r requirements.txt

Dependencies:
-------------
streamlit
requests
whois
fpdf
plotly
matplotlib
textblob
dateutil

Setup & Run:
------------
1. Download or clone the project folder.
2. Make sure the folder contains:
   - app.py
   - requirements.txt
   - fonts/NotoSans-Regular.ttf
3. Install dependencies:
   pip install -r requirements.txt
4. Run the app:
   streamlit run app.py
5. Open the URL shown in your browser to access the dashboard.

Demo Data:
----------
- Demo URLs and emails are pre-filled in the sidebar.
- PDF report generation is enabled and works with embedded charts.

Notes:
------
- VirusTotal and AbuseIPDB APIs require keys (pre-filled in this project for demo purposes).
- The app can run offline for demo emails/text analysis (without API keys).
- Ensure fonts folder is present for PDF generation (NotoSans-Regular.ttf).
