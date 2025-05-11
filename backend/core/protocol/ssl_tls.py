import ssl
import socket
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SSLAnalyzer:
    def __init__(self):
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def analyze(self, hostname: str, port: int = 443) -> dict:
        results = {}
        # Coba berbagai versi TLS
        for tls_version in [ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1]:
            try:
                context = ssl.SSLContext(tls_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Format tanggal sertifikat
                        def parse_date(date_str):
                            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                        
                        results = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version'),
                            'serialNumber': cert.get('serialNumber'),
                            'notBefore': parse_date(cert['notBefore']).isoformat(),
                            'notAfter': parse_date(cert['notAfter']).isoformat(),
                            'cipher': ssock.cipher(),
                            'protocol': ssock.version(),
                            'altNames': self._get_alt_names(cert),
                            'tls_version': tls_version
                        }
                        break  # Berhenti jika berhasil
            except Exception as e:
                continue  # Coba versi berikutnya
    
        if not results:
            return {'error': 'Could not establish SSL/TLS connection with any supported protocol'}
        return results