from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
import threading
import sqlite3
from datetime import datetime
import database
import ids_engine
import os

app = Flask(__name__)
app.secret_key = 'netsentinel_secret_key'

# Login credentials
USERNAME = "admin"
PASSWORD = "admin123"

# Store wifi data from NodeMCU
wifi_networks = []

# --- Email Alert Config ---
EMAIL_SENDER = "netsentinelwork@gmail.com"
EMAIL_PASSWORD = "nzbf peeo lpgk krfy"
EMAIL_RECEIVER = "netsentinelwork@gmail.com"

def send_email_alert(attack_type, src_ip, severity):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = f"🚨 NetSentinel Alert — {attack_type} Detected!"
        body = f"""
        ⚠️ THREAT DETECTED — NetSentinel IDS

        Attack Type : {attack_type}
        Source IP   : {src_ip}
        Severity    : {severity}
        Time        : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        Please check your dashboard immediately.
        http://127.0.0.1:5000
        """
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print(f"[EMAIL] Alert sent for {attack_type}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

# --- Protect dashboard ---
@app.before_request
def check_login():
    open_endpoints = ('login', 'static', 'receive_wifi', 'get_wifi')
    if request.endpoint not in open_endpoints and not session.get('logged_in'):
        return redirect(url_for('login'))

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="❌ Wrong username or password!")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/api/alerts')
def get_alerts():
    alerts = database.get_alerts()
    alert_list = []
    for row in alerts:
        alert_list.append({
            "id": row[0],
            "timestamp": row[1],
            "src_ip": row[2],
            "attack_type": row[3],
            "severity": row[4]
        })
    return jsonify(alert_list)

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()
    return jsonify({"status": "cleared"})

@app.route('/api/block', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip = data.get('ip')
    try:
        import subprocess
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=Block_{ip}',
            'dir=in',
            'action=block',
            f'remoteip={ip}'
        ], check=True)
        print(f"[FIREWALL] Blocked IP: {ip}")
        return jsonify({"status": "blocked", "ip": ip})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/wifi', methods=['POST'])
@app.route('/api/wifi/', methods=['POST'])
def receive_wifi():
    global wifi_networks
    print("[WIFI] Received data from NodeMCU!")
    data = request.get_json(force=True)
    print(f"[WIFI] Data: {data}")
    wifi_networks = []

    if not data:
        print("[WIFI] No data received!")
        return jsonify({"status": "no data"})

    for network in data:
        threat = "None"
        severity = "Safe"

        if network['open']:
            threat = "Open Network"
            severity = "Medium"

        ssids = [n['ssid'] for n in data]
        if ssids.count(network['ssid']) > 1:
            threat = "Possible Evil Twin Attack"
            severity = "High"

        wifi_networks.append({
            "ssid": network['ssid'],
            "rssi": network['rssi'],
            "open": network['open'],
            "threat": threat,
            "severity": severity
        })

    print(f"[WIFI] Stored {len(wifi_networks)} networks!")
    return jsonify({"status": "received"})

@app.route('/api/wifi/data')
def get_wifi():
    return jsonify(wifi_networks)

@app.route('/api/location/<ip>')
def get_location(ip):
    try:
        import requests
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return jsonify({
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "country": data.get("country", "Unknown"),
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
            "isp": data.get("isp", "Unknown")
        })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/stats')
def stats():
    return render_template('stats.html')

@app.route('/api/stats')
def get_stats():
    conn = sqlite3.connect('alerts.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM alerts')
    total = cursor.fetchone()[0]
    cursor.execute('SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type')
    by_type = cursor.fetchall()
    cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
    by_severity = cursor.fetchall()
    cursor.execute('''
        SELECT strftime('%H', timestamp) as hour, COUNT(*)
        FROM alerts GROUP BY hour ORDER BY hour
    ''')
    by_hour = cursor.fetchall()
    cursor.execute('''
        SELECT src_ip, COUNT(*) as count
        FROM alerts GROUP BY src_ip
        ORDER BY count DESC LIMIT 5
    ''')
    top_ips = cursor.fetchall()
    conn.close()
    return jsonify({
        "total": total,
        "by_type": [{"type": r[0], "count": r[1]} for r in by_type],
        "by_severity": [{"severity": r[0], "count": r[1]} for r in by_severity],
        "by_hour": [{"hour": r[0], "count": r[1]} for r in by_hour],
        "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips]
    })

@app.route('/api/export/pdf')
def export_pdf():
    alerts = database.get_alerts()
    filename = "NetSentinel_Report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("NetSentinel IDS - Threat Report", styles['Title']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))
    data = [['#', 'Timestamp', 'Source IP', 'Attack Type', 'Severity']]
    for row in alerts:
        data.append([str(row[0]), row[1], row[2], row[3], row[4]])
    table = Table(data, colWidths=[30, 150, 100, 150, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f5f5f5'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
    ]))
    elements.append(table)
    doc.build(elements)
    return send_file(filename, as_attachment=True)

# --- Start everything ---
if __name__ == '__main__':
    database.init_db()
    ids_thread = threading.Thread(target=ids_engine.start_ids, daemon=True)
    ids_thread.start()
    print("[SERVER] Dashboard running at http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0')