"""
URL Feature Extractor for Phishing Detection
Extracts URL-based, DNS, and SSL/TLS features from a given URL.
"""

import re
import ssl
import socket
import hashlib
import requests
import dns.resolver
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional


# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site',
    'icu', 'buzz', 'fun', 'space', 'live', 'click', 'link', 'info', 'biz',
    'ws', 'cc', 'pw', 'ru', 'cn'
}

# Phishing keywords
PHISHING_KEYWORDS = [
    'secure', 'account', 'update', 'confirm', 'login', 'verify', 'banking',
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'signin', 'signup', 'password', 'credential', 'free', 'winner', 'prize',
    'urgent', 'limited', 'offer', 'click', 'validate', 'suspended', 'alert'
]

# Brand names (for look-alike detection)
BRAND_NAMES = [
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'twitter', 'instagram', 'netflix', 'spotify', 'dropbox', 'gmail', 'yahoo',
    'bing', 'outlook', 'office365', 'wellsfargo', 'chase', 'bankofamerica',
    'citibank', 'hsbc', 'barclays', 'dhl', 'fedex', 'ups', 'usps'
]


class URLFeatureExtractor:
    """Extract features from a URL for ML-based phishing detection."""

    def __init__(self, url: str):
        self.original_url = url
        self.url = url.strip()
        try:
            self.parsed = urllib.parse.urlparse(self.url)
        except Exception:
            self.parsed = None
        self._domain = None
        self._tld = None

    # ------------------------------------------------------------------ #
    # Basic helpers
    # ------------------------------------------------------------------ #

    @property
    def domain(self) -> str:
        if self._domain is None and self.parsed:
            host = self.parsed.netloc.lower()
            # Strip port
            if ':' in host:
                host = host.rsplit(':', 1)[0]
            # Strip www.
            if host.startswith('www.'):
                host = host[4:]
            self._domain = host
        return self._domain or ''

    @property
    def tld(self) -> str:
        if self._tld is None:
            parts = self.domain.split('.')
            self._tld = parts[-1] if parts else ''
        return self._tld

    # ------------------------------------------------------------------ #
    # URL structure features
    # ------------------------------------------------------------------ #

    def url_length(self) -> int:
        return len(self.url)

    def domain_length(self) -> int:
        return len(self.domain)

    def is_domain_ip(self) -> int:
        """Return 1 if the domain is an IP address."""
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )
        return 1 if ip_pattern.match(self.domain) else 0

    def is_https(self) -> int:
        return 1 if self.parsed and self.parsed.scheme == 'https' else 0

    def has_at_sign(self) -> int:
        return 1 if '@' in self.url else 0

    def has_double_slash_redirect(self) -> int:
        path = self.parsed.path if self.parsed else ''
        return 1 if '//' in path else 0

    def hyphen_in_domain(self) -> int:
        return 1 if '-' in self.domain else 0

    def num_hyphens_in_domain(self) -> int:
        return self.domain.count('-')

    def num_dots_in_url(self) -> int:
        return self.url.count('.')

    def num_dots_in_domain(self) -> int:
        return self.domain.count('.')

    def num_subdomains(self) -> int:
        parts = self.domain.split('.')
        return max(0, len(parts) - 2)

    def tld_length(self) -> int:
        return len(self.tld)

    def is_suspicious_tld(self) -> int:
        return 1 if self.tld.lower() in SUSPICIOUS_TLDS else 0

    def num_digits_in_url(self) -> int:
        return sum(1 for c in self.url if c.isdigit())

    def digit_ratio_in_url(self) -> float:
        return self.num_digits_in_url() / max(len(self.url), 1)

    def num_letters_in_url(self) -> int:
        return sum(1 for c in self.url if c.isalpha())

    def letter_ratio_in_url(self) -> float:
        return self.num_letters_in_url() / max(len(self.url), 1)

    def num_special_chars(self) -> int:
        special = re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', self.url)
        return len(special)

    def special_char_ratio(self) -> float:
        return self.num_special_chars() / max(len(self.url), 1)

    def num_equals_in_url(self) -> int:
        return self.url.count('=')

    def num_qmarks_in_url(self) -> int:
        return self.url.count('?')

    def num_ampersands_in_url(self) -> int:
        return self.url.count('&')

    def has_port(self) -> int:
        return 1 if self.parsed and self.parsed.port else 0

    def is_shortening_service(self) -> int:
        shorteners = {
            'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae',
            'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc', 'u.to',
            'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co',
            'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com',
            'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net'
        }
        return 1 if self.domain in shorteners else 0

    def has_phishing_keyword(self) -> int:
        url_lower = self.url.lower()
        return 1 if any(kw in url_lower for kw in PHISHING_KEYWORDS) else 0

    def num_phishing_keywords(self) -> int:
        url_lower = self.url.lower()
        return sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)

    def has_brand_in_subdomain(self) -> int:
        subdomain = '.'.join(self.domain.split('.')[:-2]) if len(self.domain.split('.')) > 2 else ''
        return 1 if any(b in subdomain.lower() for b in BRAND_NAMES) else 0

    def has_obfuscation(self) -> int:
        """Detect hex/unicode encoding."""
        return 1 if re.search(r'%[0-9a-fA-F]{2}', self.url) else 0

    def num_obfuscated_chars(self) -> int:
        return len(re.findall(r'%[0-9a-fA-F]{2}', self.url))

    def has_encoded_chars(self) -> int:
        return 1 if re.search(r'&#[0-9]+;|&[a-z]+;', self.url) else 0

    def path_length(self) -> int:
        return len(self.parsed.path) if self.parsed else 0

    def path_depth(self) -> int:
        path = self.parsed.path if self.parsed else ''
        return len([p for p in path.split('/') if p])

    def query_length(self) -> int:
        return len(self.parsed.query) if self.parsed else 0

    def num_query_params(self) -> int:
        query = self.parsed.query if self.parsed else ''
        return len([p for p in query.split('&') if p])

    def has_suspicious_extension(self) -> int:
        suspicious_ext = ['.exe', '.php', '.js', '.cgi', '.asp', '.aspx', '.swf', '.sh']
        path = self.parsed.path.lower() if self.parsed else ''
        return 1 if any(path.endswith(ext) for ext in suspicious_ext) else 0

    def has_multiple_subdomains(self) -> int:
        return 1 if self.num_subdomains() >= 3 else 0

    def url_entropy(self) -> float:
        """Shannon entropy of the URL — high entropy = random-looking URL."""
        import math
        if not self.url:
            return 0.0
        freq = {}
        for c in self.url:
            freq[c] = freq.get(c, 0) + 1
        length = len(self.url)
        return -sum((f / length) * math.log2(f / length) for f in freq.values())

    def has_long_domain(self) -> int:
        return 1 if len(self.domain) > 30 else 0

    # ------------------------------------------------------------------ #
    # All features bundled
    # ------------------------------------------------------------------ #

    def extract_url_features(self) -> Dict[str, Any]:
        """Return all URL-based features as a dictionary."""
        return {
            'URLLength': self.url_length(),
            'DomainLength': self.domain_length(),
            'IsDomainIP': self.is_domain_ip(),
            'TLDLength': self.tld_length(),
            'NoOfSubDomain': self.num_subdomains(),
            'IsHTTPS': self.is_https(),
            'HasAtSign': self.has_at_sign(),
            'HasDoubleSlashRedirect': self.has_double_slash_redirect(),
            'HyphenInDomain': self.hyphen_in_domain(),
            'NoOfHyphensInDomain': self.num_hyphens_in_domain(),
            'NoOfDotsInURL': self.num_dots_in_url(),
            'NoOfDotsInDomain': self.num_dots_in_domain(),
            'IsSuspiciousTLD': self.is_suspicious_tld(),
            'NoOfDegitsInURL': self.num_digits_in_url(),
            'DegitRatioInURL': self.digit_ratio_in_url(),
            'NoOfLettersInURL': self.num_letters_in_url(),
            'LetterRatioInURL': self.letter_ratio_in_url(),
            'NoOfSpecialChars': self.num_special_chars(),
            'SpacialCharRatioInURL': self.special_char_ratio(),
            'NoOfEqualsInURL': self.num_equals_in_url(),
            'NoOfQMarkInURL': self.num_qmarks_in_url(),
            'NoOfAmpersandInURL': self.num_ampersands_in_url(),
            'HasPort': self.has_port(),
            'IsShorteningService': self.is_shortening_service(),
            'HasPhishingKeyword': self.has_phishing_keyword(),
            'NoOfPhishingKeywords': self.num_phishing_keywords(),
            'HasBrandInSubdomain': self.has_brand_in_subdomain(),
            'HasObfuscation': self.has_obfuscation(),
            'NoOfObfuscatedChar': self.num_obfuscated_chars(),
            'HasEncodedChars': self.has_encoded_chars(),
            'PathLength': self.path_length(),
            'PathDepth': self.path_depth(),
            'QueryLength': self.query_length(),
            'NoOfQueryParams': self.num_query_params(),
            'HasSuspiciousExtension': self.has_suspicious_extension(),
            'HasMultipleSubdomains': self.has_multiple_subdomains(),
            'URLEntropy': self.url_entropy(),
            'HasLongDomain': self.has_long_domain(),
        }


class SecurityAssessor:
    """Perform live security assessment on a URL."""

    def __init__(self, url: str, timeout: int = 8):
        self.url = url.strip()
        self.timeout = timeout
        try:
            self.parsed = urllib.parse.urlparse(self.url)
        except Exception:
            self.parsed = None
        self._extractor = URLFeatureExtractor(self.url)

    @property
    def domain(self) -> str:
        return self._extractor.domain

    # ------------------------------------------------------------------ #
    # DNS check
    # ------------------------------------------------------------------ #

    def check_dns(self) -> Dict[str, Any]:
        result = {
            'has_dns': False,
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'error': None
        }
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout

            # A records
            try:
                a_ans = resolver.resolve(self.domain, 'A')
                result['a_records'] = [str(r) for r in a_ans]
                result['has_dns'] = True
            except Exception:
                pass

            # MX records
            try:
                mx_ans = resolver.resolve(self.domain, 'MX')
                result['mx_records'] = [str(r.exchange) for r in mx_ans]
            except Exception:
                pass

            # NS records
            try:
                ns_ans = resolver.resolve(self.domain, 'NS')
                result['ns_records'] = [str(r) for r in ns_ans]
            except Exception:
                pass

            # TXT records (SPF, DMARC hints)
            try:
                txt_ans = resolver.resolve(self.domain, 'TXT')
                result['txt_records'] = [str(r) for r in txt_ans]
            except Exception:
                pass

        except Exception as e:
            result['error'] = str(e)

        return result

    # ------------------------------------------------------------------ #
    # SSL / TLS check
    # ------------------------------------------------------------------ #

    def check_ssl(self) -> Dict[str, Any]:
        result = {
            'has_ssl': False,
            'is_valid': False,
            'issuer': None,
            'subject': None,
            'expires': None,
            'days_to_expiry': None,
            'is_expired': None,
            'error': None
        }

        if not self.parsed or self.parsed.scheme != 'https':
            result['error'] = 'Not an HTTPS URL'
            return result

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    result['has_ssl'] = True
                    result['is_valid'] = True

                    # Issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['issuer'] = issuer.get('organizationName', 'Unknown')

                    # Subject
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['subject'] = subject.get('commonName', 'Unknown')

                    # Expiry
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result['expires'] = expiry_dt.strftime('%Y-%m-%d')
                        delta = expiry_dt - datetime.utcnow()
                        result['days_to_expiry'] = delta.days
                        result['is_expired'] = delta.days < 0

        except ssl.SSLCertVerificationError as e:
            result['has_ssl'] = True
            result['is_valid'] = False
            result['error'] = f'Invalid certificate: {e}'
        except Exception as e:
            result['error'] = str(e)

        return result

    # ------------------------------------------------------------------ #
    # HTTP / redirect check
    # ------------------------------------------------------------------ #

    def check_redirects(self) -> Dict[str, Any]:
        result = {
            'final_url': None,
            'num_redirects': 0,
            'redirect_chain': [],
            'status_code': None,
            'error': None
        }
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; PhishingDetector/1.0)'}
            resp = requests.get(
                self.url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False   # for analysis purposes
            )
            result['final_url'] = resp.url
            result['status_code'] = resp.status_code
            result['redirect_chain'] = [r.url for r in resp.history]
            result['num_redirects'] = len(resp.history)
        except requests.exceptions.TooManyRedirects as e:
            result['error'] = 'Too many redirects'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ------------------------------------------------------------------ #
    # PhishTank reputation check
    # ------------------------------------------------------------------ #

    def check_phishtank(self) -> Dict[str, Any]:
        """Check URL against PhishTank API (no key needed for basic check)."""
        result = {
            'in_phishtank': False,
            'phishtank_verified': False,
            'error': None
        }
        try:
            api_url = 'https://checkurl.phishtank.com/checkurl/'
            url_hash = hashlib.md5(self.url.encode('utf-8')).hexdigest()
            payload = {
                'url': self.url,
                'format': 'json',
                'app_key': ''
            }
            resp = requests.post(api_url, data=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get('results', {})
                result['in_phishtank'] = results.get('in_database', False)
                result['phishtank_verified'] = results.get('verified', False)
        except Exception as e:
            result['error'] = str(e)
        return result

    # ------------------------------------------------------------------ #
    # Full security report
    # ------------------------------------------------------------------ #

    def full_assessment(self) -> Dict[str, Any]:
        """Run all checks and return a combined security report."""
        extractor = self._extractor
        url_features = extractor.extract_url_features()

        dns_info = self.check_dns()
        ssl_info = self.check_ssl()
        redirect_info = self.check_redirects()
        phishtank_info = self.check_phishtank()

        # Heuristic risk flags
        risk_flags = []
        if url_features['IsDomainIP']:
            risk_flags.append('Domain is an IP address')
        if url_features['IsSuspiciousTLD']:
            risk_flags.append(f'Suspicious TLD: .{extractor.tld}')
        if url_features['HasAtSign']:
            risk_flags.append('URL contains @ sign')
        if url_features['IsShorteningService']:
            risk_flags.append('URL shortening service detected')
        if url_features['HasObfuscation']:
            risk_flags.append('URL contains obfuscated characters')
        if url_features['HasPhishingKeyword']:
            risk_flags.append('Phishing keywords found in URL')
        if url_features['HasBrandInSubdomain']:
            risk_flags.append('Brand name in subdomain (look-alike)')
        if url_features['URLLength'] > 100:
            risk_flags.append('Unusually long URL')
        if url_features['NoOfSubDomain'] >= 3:
            risk_flags.append('Excessive subdomains')
        if url_features['HyphenInDomain']:
            risk_flags.append('Hyphen in domain name')
        if not dns_info['has_dns']:
            risk_flags.append('No DNS records found')
        if ssl_info.get('is_expired'):
            risk_flags.append('SSL certificate is expired')
        if ssl_info.get('days_to_expiry') is not None and 0 < ssl_info['days_to_expiry'] < 30:
            risk_flags.append('SSL certificate expiring within 30 days')
        if redirect_info['num_redirects'] > 3:
            risk_flags.append(f'Multiple redirects: {redirect_info["num_redirects"]}')
        if phishtank_info['in_phishtank']:
            risk_flags.append('URL found in PhishTank database')

        return {
            'url': self.url,
            'domain': extractor.domain,
            'tld': extractor.tld,
            'url_features': url_features,
            'dns': dns_info,
            'ssl': ssl_info,
            'redirects': redirect_info,
            'phishtank': phishtank_info,
            'risk_flags': risk_flags,
            'risk_score': len(risk_flags),
        }

