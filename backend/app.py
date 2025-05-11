from ipaddress import ip_address
from flask import Flask, g, render_template, request, jsonify, send_from_directory, Blueprint
from flask_cors import CORS
import geoip2
from core.scanner import PortScanner
from core.protocol.http import HTTPAnalyzer
from core.protocol.ssl_tls import SSLAnalyzer
from core.geoip_lookup import GeoIPLookup
from db.models import db, Target, Port, HttpInfo, SSLCert, Vulnerability
from config import SCANNER_CONFIG
import asyncio
from datetime import datetime
import os
import logging
from flask_caching import Cache  # Gunakan Flask-Caching

#Log Debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan_debug.log'),
        logging.StreamHandler()
    ]
)

# Inisialisasi Flask
app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
CORS(app)

# Konfigurasi database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///minishodan.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Inisialisasi cache
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})  # Gunakan SimpleCache dari Flask-Caching

# Inisialisasi scanner
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/scan')
def scan_page():
    return render_template('scan.html')

@app.route('/results/<int:scan_id>')
def scan_results(scan_id):
    scan = Target.query.get_or_404(scan_id)
    ports = Port.query.filter_by(target_id=scan_id).all()
    
    # Format data untuk template
    port_data = []
    for port in ports:
        port_info = {
            'port': port.port,
            'banner': port.banner,
            'status': port.status,
            'service_name': port.service_name,
            'service_display_name': get_service_display_name(port),  # Use the function we defined
            'version': port.version,
            'http_info': None,
            'ssl_cert': None
        }
        
        if port.http_info:
            port_info['http_info'] = {
                'title': port.http_info.title,
                'server': port.http_info.server,
                'tech_stack': port.http_info.tech_stack
            }
            
        if port.ssl_cert:
            port_info['ssl_cert'] = {
                'subject': port.ssl_cert.subject,
                'issuer': port.ssl_cert.issuer,
                'valid_to': port.ssl_cert.valid_to,
                'cipher': port.ssl_cert.cipher
            }
        
        port_data.append(port_info)
    
    return render_template('results.html', scan=scan, ports=port_data)

# Move this function outside of the route
def get_service_display_name(port):
    common_ports = {
        # Web & HTTP(S) Services
        80: "HTTP",
        81: "HTTP Alt",
        88: "Kerberos",
        443: "HTTPS",
        591: "FileMaker",
        593: "RPC over HTTP",
        8000: "HTTP-Alt",
        8008: "HTTP-Proxy",
        8080: "HTTP Proxy",
        8081: "HTTP Mgmt",
        8088: "Web Server",
        8443: "HTTPS-Alt",
        8888: "HTTP Dev",
        9000: "SonarQube / Web Apps",
        9080: "HTTP Jetty",
        9443: "HTTPS Jetty",
        10000: "Webmin",
        
        # FTP / File Sharing
        20: "FTP Data",
        21: "FTP Control",
        210: "FTP Data (Passive)",
        69: "TFTP",
        137: "NetBIOS Name",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        445: "SMB",
        2049: "NFS",
        2121: "FTP Alt",
        548: "AFP (Apple File Protocol)",

        # SSH / Remote Access
        22: "SSH",
        220: "SSH Alt",
        23: "Telnet",
        230: "Telnet Alt",
        2222: "SSH Alt / Admin",
        3389: "RDP",
        5900: "VNC",
        5800: "VNC Web",
        5985: "WinRM (HTTP)",
        5986: "WinRM (HTTPS)",
        7680: "Remote Desktop Services",

        # Mail Protocols
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",

        # DNS, Directory, Network Services
        53: "DNS",
        123: "NTP",
        161: "SNMP",
        162: "SNMP Trap",
        389: "LDAP",
        636: "LDAPS",
        500: "IKE (IPsec)",
        514: "Syslog",
        520: "RIP",
        1701: "L2TP",
        1812: "RADIUS (Auth)",
        1813: "RADIUS (Acct)",
        4500: "IPSec NAT-T",

        # Databases
        1433: "MSSQL",
        1521: "Oracle DB",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        5000: "CouchDB / Flask / Dev",
        9042: "Cassandra",
        11211: "Memcached",

        # DevOps & Containers
        2375: "Docker API (Unsecured)",
        2376: "Docker API (TLS)",
        2380: "etcd",
        4001: "etcd Alt",
        7001: "Consul",
        8500: "Consul UI",
        8600: "Consul DNS",
        10250: "Kubernetes Kubelet",
        10255: "Kubelet ReadOnly",
        3000: "Grafana",
        5601: "Kibana",
        9200: "Elasticsearch",
        9300: "Elastic Transport",
        15672: "RabbitMQ Management",

        # Messaging & Chat
        1883: "MQTT",
        5222: "XMPP",
        6660: "IRC",
        6667: "IRC",
        6697: "IRC SSL",
        8009: "AJP13 (Tomcat)",
        50000: "SAP Dispatcher",

        # Exploitable / CTF Favorite Ports
        111: "rpcbind",
        512: "exec",
        513: "login",
        514: "shell",
        1099: "RMI",
        2049: "NFS",
        4444: "Metasploit Handler",
        5555: "Android Debug Bridge",
        6000: "X11",
        7000: "Cisco Mgmt",
        32764: "Linksys Backdoor",
        4786: "Cisco Smart Install",
        1900: "UPnP SSDP",
        17500: "Dropbox",
        646: "LDP (Mikrotik)",
        161: "SNMP v2",
        22222: "SSH Honeypot / Test",
        31337: "Back Orifice"

        # 🚨 You can keep going... up to your RAM's patience 😆
    }


    return common_ports.get(port.port, port.service_name or "Unknown")
logging.basicConfig(level=logging.DEBUG)
@app.before_request
def handle_geoip():
    try:
        g.geoip = GeoIPLookup()
        if not g.geoip.reader:
            logging.warning("GeoIP database not available - geolocation disabled")
    except Exception as e:
        logging.warning(f"GeoIP initialization failed: {str(e)}")
        g.geoip = None
        
@app.route('/api/scan', methods=['POST'])
def api_scan():
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    # Cek apakah IP sedang diproses
    if cache.get(ip):
        return jsonify({'error': 'Scan already in progress for this IP'}), 429

    # Tandai IP sebagai sedang diproses
    cache.set(ip, True, timeout=300)  # Timeout 5 menit

    try:
        logging.debug("Starting scan...")
        data = request.json
        port_range = data.get('port_range', '1-1024')

        # Parse port range
        start_port, end_port = map(int, port_range.split('-'))
        ports = list(range(start_port, end_port + 1))

        # Buat target di database
        target = Target(
            ip_address=ip,
            timestamp=datetime.utcnow()
        )
        db.session.add(target)
        db.session.commit()

        # Inisialisasi scanner dan analyzer
        scanner = PortScanner(
            max_threads=SCANNER_CONFIG['max_threads'],
            timeout=SCANNER_CONFIG['timeout'],
            skip_admin_ports=SCANNER_CONFIG['skip_admin_ports']
        )
        http_analyzer = HTTPAnalyzer()
        ssl_analyzer = SSLAnalyzer()
        geoip = GeoIPLookup()

        # Lakukan pemindaian GeoIP
        geo_data = geoip.lookup(ip)
        if geo_data:
            target.location = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
            target.isp = geo_data.get('asn', {}).get('organization', 'Unknown') or "Unknown"
            target.asn = f"AS{geo_data.get('asn', {}).get('number', '')}" or "Unknown"
        else:
            target.location = "Unknown (GeoIP DB not available)"
            target.isp = "Unknown"
            target.asn = "Unknown"
            db.session.add(target)
            db.session.commit()

        # Lakukan pemindaian port
        # Gunakan sync version
        logging.debug(f"Scanning IP: {ip} on ports: {ports}")
        port_results = scanner.scan_ports_sync(ip, ports)

        for result in port_results:
            if result['status'] == 'open':
                try:
                    port = Port(
                        target_id=target.id,
                        port=result['port'],
                        status=result['status'],
                        banner=scanner.get_banner(ip, result['port']) if result['port'] != 443 else ""
                    )
                    db.session.add(port)
                except Exception as e:
                    logging.error(f"Error adding port {result['port']} for IP {ip}: {str(e)}")
            
            # Untuk port 443, gunakan SSL analyzer khusus
            if result['port'] == 443:
                try:
                    ssl_data = ssl_analyzer.analyze(ip, result['port'])
                    if ssl_data and 'error' not in ssl_data:
                        ssl_cert = SSLCert(
                            port_id=port.id,
                            issuer=ssl_data.get('issuer', {}).get('commonName', 'Unknown'),
                            subject=ssl_data.get('subject', {}).get('commonName', 'Unknown'),
                            valid_from=ssl_data.get('notBefore', 'Unknown'),
                            valid_to=ssl_data.get('notAfter', 'Unknown'),
                            cipher=ssl_data.get('cipher', ['Unknown'])[0],
                            protocol_version=ssl_data.get('protocol', 'Unknown')
                        )
                        db.session.add(ssl_cert)
                except Exception as e:
                    logging.error(f"SSL analysis failed for {ip}:443 - {str(e)}")
                    port.banner = f"SSL Analysis Error: {str(e)}"
                
                # Analisis HTTP untuk port web
                if result['port'] in [80, 443, 8080, 8443]:
                    try:
                        protocol = 'https' if result['port'] in [443, 8443] else 'http'
                        url = f"{protocol}://{ip}:{result['port']}"
                        
                        http_data = http_analyzer.analyze(url)
                        if http_data and 'error' not in http_data:
                            http_info = HttpInfo(
                                port_id=port.id,
                                title=http_data.get('title'),
                                server=http_data.get('server'),
                                tech_stack=', '.join(http_data.get('tech_stack', [])),
                                headers=str(http_data.get('headers', {}))
                            )
                            db.session.add(http_info)
                    except Exception as e:
                        logging.error(f"HTTP analysis failed for {url}: {str(e)}")
                
                # Analisis SSL untuk port HTTPS
                if result['port'] in [443, 8443]:
                    try:
                        ssl_data = ssl_analyzer.analyze(ip, result['port'])
                        if ssl_data and 'error' not in ssl_data:
                            ssl_cert = SSLCert(
                                port_id=port.id,
                                issuer=ssl_data.get('issuer', {}).get('commonName', 'Unknown'),
                                subject=ssl_data.get('subject', {}).get('commonName', 'Unknown'),
                                valid_from=ssl_data.get('notBefore', 'Unknown'),
                                valid_to=ssl_data.get('notAfter', 'Unknown'),
                                cipher=ssl_data.get('cipher', ['Unknown'])[0],
                                protocol_version=ssl_data.get('protocol', 'Unknown')
                            )
                            db.session.add(ssl_cert)
                    except Exception as e:
                        logging.error(f"SSL analysis failed for {ip}:{result['port']}: {str(e)}")
                            
                            # Coba dapatkan banner HTTPS
                        https_url = f"https://{ip}:{result['port']}"
                        http_data = http_analyzer.analyze(https_url)
                        if http_data and 'error' not in http_data:
                                http_info = HttpInfo(
                                    port_id=port.id,
                                    title=http_data.get('title', ''),
                                    server=http_data.get('server', ''),
                                    tech_stack=', '.join(http_data.get('tech_stack', []))
                                )
                                db.session.add(http_info)
                    except Exception as e:
                        logging.error(f"HTTPS analysis failed for {ip}:{result['port']}: {str(e)}")
                
                # Analisis vulnerabilities jika ada
                if 'vulnerabilities' in result and result['vulnerabilities']:
                    for vuln in result['vulnerabilities']:
                        vulnerability = Vulnerability(
                            port_id=port.id,
                            name=vuln.get('name', ''),
                            description=vuln.get('description', ''),
                            severity=vuln.get('severity', '')
                        )
                        db.session.add(vulnerability)
        
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Scan completed successfully',
            'ip': ip,
            'timestamp': target.timestamp.isoformat(),
            'location': target.location,
            'scan_id': target.id,
            'open_ports': len([p for p in port_results if p['status'] == 'open'])
        })

    except Exception as e:
        db.session.rollback()
        logging.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

    finally:
        cache.delete(ip)  # Hapus tanda setelah selesai

@app.route('/api/scans')
def get_scans():
    # Ambil 10 pemindaian terakhir dari database
    scans = Target.query.order_by(Target.timestamp.desc()).limit(10).all()
    
    # Inisialisasi GeoIP lookup jika diperlukan
    geoip = GeoIPLookup()  # Gunakan kelas GeoIPLookup yang sudah ada
    
    results = []
    for scan in scans:
        # Jika ingin menambahkan geolokasi untuk setiap scan
        if geoip.reader:  # Jika GeoIP database tersedia
            geo_data = geoip.lookup(scan.ip_address)
            if geo_data:
                scan.location = f"{geo_data.get('city', '')}, {geo_data.get('country', '')}"
                db.session.commit()  # Simpan update lokasi
        
        results.append({
            'id': scan.id,
            'ip': scan.ip_address,
            'location': scan.location or "Unknown",
            'timestamp': scan.timestamp.isoformat(),
            'port_count': len(scan.ports)
        })
    
    return jsonify(results)

@app.route('/api/scan/<int:scan_id>')
def get_scan_details(scan_id):
    scan = Target.query.get_or_404(scan_id)
    
    ports = []
    for port in scan.ports:
        port_data = {
            'port': port.port,
            'banner': port.banner,
            'service': port.service_name,
            'http': None,
            'ssl': None,
            'vulnerabilities': []
        }
        
        if port.http_info:
            port_data['http'] = {
                'title': port.http_info.title,
                'server': port.http_info.server,
                'tech': port.http_info.tech_stack
            }
        
        if port.ssl_cert:
            port_data['ssl'] = {
                'issuer': port.ssl_cert.issuer,
                'valid_to': port.ssl_cert.valid_to,
                'cipher': port.ssl_cert.cipher
            }
        
        ports.append(port_data)
    
    return jsonify({
        'ip': scan.ip_address,
        'location': scan.location,
        'isp': scan.isp,
        'asn': scan.asn,
        'timestamp': scan.timestamp.isoformat(),
        'ports': ports
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)