import asyncio
import socket
from asyncio import Semaphore
from concurrent.futures import ThreadPoolExecutor
import ssl
from typing import List, Dict, Optional
from datetime import datetime
import geoip2.database
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PortScanner:
    def __init__(self, max_threads=100, timeout=2.0, skip_admin_ports=True):
        self.max_threads = max_threads
        self.timeout = timeout
        self.skip_admin_ports = skip_admin_ports
        self.admin_ports = [135, 137, 138, 139, 445]
        self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        self.executor = ThreadPoolExecutor(max_workers=self.max_threads)
        self.logger = logging.getLogger(__name__)
        self.semaphore = Semaphore(max_threads)  # Batasi jumlah proses paralel
        
    async def check_port(self, ip: str, port: int) -> Optional[Dict]:
        if self.skip_admin_ports and port in self.admin_ports:
            return {
                'port': port,
                'status': 'filtered',
                'message': 'Skipped (requires admin)'
            }
        if port < 1 or port > 65535:
            return {
                'port': port,
                'status': 'invalid',
                'message': 'Port number out of range'
            }
        if not isinstance(ip, str):
            return {
                'port': port,
                'status': 'invalid',
                'message': 'IP address must be a string'
            }
        if not ip:
            return {
                'port': port,
                'status': 'invalid',
                'message': 'IP address cannot be empty'
            }
        if not ip.replace('.', '').isdigit():
            return {
                'port': port,
                'status': 'invalid',
                'message': 'IP address must be numeric'
            }
        if not all(0 <= int(octet) < 256 for octet in ip.split('.')):
            return {
                'port': port,
                'status': 'invalid',
                'message': 'IP address is not valid'
            }
        
        async with self.semaphore:  # Gunakan semaphore untuk membatasi paralelisme
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                writer.close()
                await writer.wait_closed()
                return {'port': port, 'status': 'open'}
            except Exception:
                return {'port': port, 'status': 'closed'}
        
    async def scan_ports(self, ip: str, ports: List[int]) -> List[Dict]:
        self.logger.info(f"Starting scan on {ip} for ports {ports[0]}-{ports[-1]}")
        
        # Filter out admin ports jika diperlukan
        if self.skip_admin_ports:
            ports = [p for p in ports if p not in self.admin_ports]
        
        tasks = [self.check_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r['status'] == 'open']
        self.logger.info(f"Scan completed. Found {len(open_ports)} open ports.")
        return results

    def get_banner(self, ip: str, port: int) -> str:
        try:
            if port == 443:  # Handle khusus HTTPS
                # Buat SSL context dengan opsi modern
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.options |= ssl.OP_NO_SSLv2  # Nonaktifkan SSLv2 (tidak aman)
                context.options |= ssl.OP_NO_SSLv3  # Nonaktifkan SSLv3 (tidak aman)
                context.options |= ssl.OP_NO_TLSv1  # Nonaktifkan TLSv1 (dianggap tidak aman)
                context.options |= ssl.OP_NO_TLSv1_1  # Nonaktifkan TLSv1.1 (dianggap tidak aman)
                context.minimum_version = ssl.TLSVersion.TLSv1_2  # Hanya gunakan TLS 1.2+
            
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    try:
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            # Coba kirim request HTTPS
                            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                            ssock.send(request.encode())
                            return ssock.recv(4096).decode('utf-8', errors='ignore').strip()
                    except ssl.SSLError as e:
                        # Fallback untuk server yang lebih tua
                        if "handshake failure" in str(e):
                            return self._fallback_ssl_handshake(ip, port)
                        raise
            else:  # Handle HTTP biasa
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    s.send(f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                    return s.recv(4096).decode('utf-8', errors='ignore').strip()
        except Exception as e:
            self.logger.debug(f"Banner grab failed for {ip}:{port} - {str(e)}")
            return ""
    def _fallback_ssl_handshake(self, ip: str, port: int) -> str:
        # """Coba handshake dengan protokol yang lebih lama"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_SSLv2  # Tetap nonaktifkan SSLv2
            # Izinkan SSLv3 dan TLSv1 untuk kompatibilitas
            context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    ssock.send(request.encode())
                    return ssock.recv(4096).decode('utf-8', errors='ignore').strip()
        except Exception as e:
            self.logger.debug(f"Fallback SSL handshake failed for {ip}:{port} - {str(e)}")
            return ""
        
        
    def get_location(self, ip: str) -> Optional[Dict]:
        try:
            response = self.geoip_reader.city(ip)
            location = {
                'country': response.country.name,
                'region': response.subdivisions.most_specific.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
            self.logger.debug(f"Location for {ip}: {location}")
            return location
        except geoip2.errors.GeoIP2Error as e:
            self.logger.error(f"GeoIP error for {ip}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error retrieving location for {ip}: {e}")
            return None
        finally:
            self.geoip_reader.close()
            self.logger.debug("GeoIP reader closed.")
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            self.logger.debug("GeoIP reader re-initialized.")

    def scan_ports_sync(self, ip: str, ports: List[int]) -> List[Dict]:
        # Sync version of scan_ports
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(self.scan_ports(ip, ports))
        finally:
            loop.close()
        return results

