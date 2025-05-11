import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# GeoIP Configuration
GEOIP_DB_PATH = os.path.join(BASE_DIR, 'GeoLite2-City.mmdb')

# Fallback jika file tidak ditemukan
if not os.path.exists(GEOIP_DB_PATH):
    GEOIP_DB_PATH = None
    print("Warning: GeoIP database not found. Geolocation features will be disabled.")

# Secret key for sessions
SECRET_KEY = 'your-secret-key-here'

# Scanner configuration
SCANNER_CONFIG = {
    'default_ports': list(range(1, 1025)),
    'timeout': 2.0,
    'max_threads': 100,
    'skip_admin_ports': True
}

# API Keys (if needed)
API_KEYS = {
    'shodan': None,
    'virustotal': None
}