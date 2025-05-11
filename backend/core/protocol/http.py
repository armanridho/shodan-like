import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

class HTTPAnalyzer:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        # Disable SSL verification warning
        requests.packages.urllib3.disable_warnings()

    def analyze(self, url: str) -> dict:
        try:
            # Check if URL needs scheme
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}" if ':443' in url else f"http://{url}"
            
            # Handle SSL verification
            verify_ssl = False  # Nonaktifkan verifikasi untuk development
            if url.startswith('https://'):
                requests.packages.urllib3.disable_warnings()

            response = self.session.get(
            url,
            timeout=self.timeout,
            verify=verify_ssl,
            allow_redirects=True,
            headers={
                'User-Agent': self.session.headers['User-Agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
        )
            
            # Check if response is HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'html' not in content_type:
                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'server': response.headers.get('Server'),
                    'error': 'Non-HTML content'
                }
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'title': soup.title.string if soup.title else None,
                'server': response.headers.get('Server'),
                'tech_stack': self.detect_tech(response),
                'forms': self.extract_forms(soup, url)
            }
        except requests.exceptions.SSLError:
            logger.warning(f"SSL error for {url}")
            return {'error': 'SSL certificate verification failed'}
        except Exception as e:
            logger.error(f"HTTP analysis failed for {url}: {str(e)}")
            return {'error': str(e)}

    def detect_tech(self, response) -> list:
        tech = []
        headers = response.headers
        
        # Check common technology indicators
        if 'X-Powered-By' in headers:
            tech.append(headers['X-Powered-By'])
        if 'Server' in headers:
            tech.append(headers['Server'])
        if 'X-Generator' in headers:
            tech.append(headers['X-Generator'])
        
        # Check for common frameworks in HTML
        html = response.text.lower()
        if 'wordpress' in html:
            tech.append('WordPress')
        if 'drupal' in html:
            tech.append('Drupal')
        if 'laravel' in html:
            tech.append('Laravel')
        
        return list(set(tech))  # Remove duplicates

    def extract_forms(self, soup, base_url) -> list:
        forms = []
        for form in soup.find_all('form'):
            forms.append({
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [
                    {'name': inp.get('name'), 'type': inp.get('type')} 
                    for inp in form.find_all('input')
                ]
            })
        return forms