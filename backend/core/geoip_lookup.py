import ipaddress
from venv import logger
from config import GEOIP_DB_PATH
import logging
import geoip2.database
from typing import Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Check if the database file exists
if GEOIP_DB_PATH:
    logging.info(f"GeoIP database found at {GEOIP_DB_PATH}")
else:
    logging.warning("GeoIP database not found. Geolocation features will be disabled.")
    
class GeoIPLookup:
    def __init__(self):
        self.reader = None
        if GEOIP_DB_PATH:
            try:
                self.reader = geoip2.database.Reader(GEOIP_DB_PATH)
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {str(e)}")
                self.reader = None

    def lookup(self, ip: str):
        if not self.reader:
            return None
            
        try:
        # Skip private IPs
            if ip.startswith(('192.168.', '10.', '172.')):
                return None
            
            response = self.reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except geoip2.errors.GeoIP2Error as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {str(e)}")
            return None
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {str(e)}")
            return None

    def _get_asn(self, ip: str) -> Optional[Dict]:
        try:
            response = self.reader.asn(ip)
            return {
                'number': response.autonomous_system_number,
                'organization': response.autonomous_system_organization
            }
        except Exception:
            return None