from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from email import message_from_string
from email.policy import default
from email.utils import parseaddr
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import whois
import requests
import re
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "YOUR TOKEN")

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'frontend.html')

def extract_auth_status(header):
    return {
        'SPF': 'pass' in header.lower(),
        'DKIM': 'dkim=pass' in header.lower(),
        'DMARC': 'dmarc=pass' in header.lower()
    }

def extract_fields(msg):
    return {
        'Sender': parseaddr(msg.get('From', ''))[1],
        'Reply-To': parseaddr(msg.get('Reply-To', ''))[1],
        'Message-ID': msg.get('Message-ID', '').strip()
    }

def extract_hops(received_headers):
    hops = []
    for idx, entry in enumerate(reversed(received_headers)):
        ip_match = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', entry)
        by_match = re.search(r'by\s+([^\s\(\);]+)', entry)
        from_match = re.search(r'from\s+([^\s\(\);]+)', entry)
        date_match = re.search(r';\s*(.+)', entry)
        hops.append({
            'index': idx + 1,
            'ip': ip_match.group(1) if ip_match else '',
            'from': from_match.group(1) if from_match else '',
            'by': by_match.group(1) if by_match else '',
            'timestamp': date_match.group(1) if date_match else ''
        })
    return hops

def geolocate_ip(ip):
    try:
        url = f'https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}'
        res = requests.get(url, timeout=3)
        data = res.json()
        loc = data.get("loc", "0,0").split(",")
        city = data.get("city", "")
        region = data.get("region", "")
        country = data.get("country", "")
        print(f"Resolved IP {ip} → {city}, {region}, {country}")
        return {
            'ip': ip,
            'lat': float(loc[0]),
            'lon': float(loc[1]),
            'city': city,
            'region': region,
            'country': country
        }
    except Exception as e:
        print(f"Geolocation failed for {ip}: {e}")
        return {'ip': ip, 'lat': 0.0, 'lon': 0.0, 'city': '', 'region': '', 'country': ''}

def check_domain_age(email_address):
    try:
        domain = email_address.split('@')[-1].strip()
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return {'domain': domain, 'status': 'unknown', 'warn': False}
        days_old = (datetime.utcnow() - creation_date).days
        return {'domain': domain, 'age_days': days_old, 'status': 'ok', 'warn': days_old < 90}
    except Exception as e:
        return {'domain': '', 'status': 'unknown', 'warn': False, 'error': str(e)}

def extract_redirect_links(msg):
    html_part = msg.get_body(preferencelist=('html'))
    if not html_part:
        return []
    soup = BeautifulSoup(html_part.get_content(), 'html.parser')
    suspicious = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        parsed = urlparse(href)
        qs = parse_qs(parsed.query)
        embedded = [v for val in qs.values() for v in val if v.startswith('http')]
        if embedded or ('apple' not in parsed.netloc.lower() and 'icloud' not in parsed.netloc.lower()):
            suspicious.append({
                'href': href,
                'suspicious': True
            })
    return suspicious

@app.route('/analyze', methods=['POST'])
def analyze():
    raw_email = request.json.get('email', '')
    try:
        msg = message_from_string(raw_email, policy=default)
        header = str(msg)
        auth = extract_auth_status(header)
        fields = extract_fields(msg)
        domain_age = check_domain_age(fields['Sender'])
        hops = extract_hops(msg.get_all('Received', []))

        for hop in hops:
            if hop['ip']:
                geo = geolocate_ip(hop['ip'])
                hop.update({
                    'lat': geo['lat'],
                    'lon': geo['lon'],
                    'city': geo['city'],
                    'region': geo['region'],
                    'country': geo['country']
                })

        redirects = extract_redirect_links(msg)

        # Sort hops chronologically (earliest first)
        hops = sorted(hops, key=lambda h: h['index'])

        return jsonify({
            'auth': auth,
            'fields': fields,
            'domain_age': domain_age,
            'hops': hops,
            'redirect_links': redirects
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
