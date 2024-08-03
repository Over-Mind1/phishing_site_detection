import re
import ssl
import OpenSSL
import datetime
import requests
import socket
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return 1
    except socket.error:
        return -1

def is_long_url(url):
    if len(url) < 54:
        return 1
    elif len(url) <= 75:
        return 0
    else:
        return -1

def is_tiny_url(url):
    tiny_url_pattern = (
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|'
        r'tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|'
        r'url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|'
        r'BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|'
        r'fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|'
        r'om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|'
        r'cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|'
        r'buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|'
        r'scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|'
        r'v\.gd|link\.zip\.net'
    )
    return -1 if re.search(tiny_url_pattern, url) else 1

def has_at_symbol(url):
    return -1 if '@' in url else 1

def has_redirecting_double_slash(url):
    return -1 if url.rfind('//') > 7 else 1

def has_prefix_suffix(domain):
    return -1 if '-' in domain else 1

def count_subdomains(domain):
    subdomain_count = domain.count('.')
    return 1 if subdomain_count == 1 else -1 if subdomain_count == 2 else 0

def get_certificate_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        issuer = dict(x509.get_issuer().get_components())
        issuer_name = issuer.get(b'O').decode('utf-8')
        
        not_before = x509.get_notBefore().decode('utf-8')
        not_after = x509.get_notAfter().decode('utf-8')
        
        not_before_date = datetime.datetime.strptime(not_before, '%Y%m%d%H%M%SZ')
        not_after_date = datetime.datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        age = (datetime.datetime.utcnow() - not_before_date).days / 365
        
        return issuer_name, age, True
    except Exception as e:
        print(f"Error retrieving certificate info: {e}")
        return None, None, False

def is_https(url):
    trusted_issuers = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign"]
    minimum_age = 1  # years

    if not url.startswith("https://"):
        return -1  # Phishing

    domain = url.split("//")[-1].split("/")[0]
    issuer, age, valid = get_certificate_info(domain)
    
    if not valid:
        return -1  # Phishing
    
    if issuer in trusted_issuers:
        if age >= minimum_age:
            return 1  # Legitimate
        else:
            return -1  # Phishing
    else:
        return 0  # Suspicious

def domain_registration_length(domain):
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        age = (expiration_date - creation_date).days / 365
        return 1 if age >= 1 else -1
    except:
        return 0

def has_favicon(url, domain):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        icon_link = soup.find("link", rel="shortcut icon")
        if icon_link:
            icon_url = urlparse(icon_link['href']).netloc
            return -1 if icon_url and icon_url != domain else 1
    except:
        return 0

def is_non_standard_port(url):
    non_standard_ports = {21, 22, 23,80,443,445, 1433, 1521, 3306, 3389}
    port = urlparse(url).port
    return -1 if port and port in non_standard_ports else 1

def has_https_token(domain):
    return -1 if 'http' in domain else 1

def calculate_request_url(soup, domain):
    try:
        total_links = len(soup.find_all(['img', 'audio', 'embed', 'iframe']))
        external_links = sum(
            1 for tag in soup.find_all(['img', 'audio', 'embed', 'iframe'])
            if urlparse(tag.get('src')).netloc != domain
        )
        if total_links == 0:
            return -1
        percent_external = (external_links / total_links) * 100
        if percent_external < 22:
            return 1
        elif percent_external <= 61:
            return 0
        else:
            return -1
    except:
        return 1

def calculate_url_of_anchor(soup, domain):
    try:
        total_anchors = len(soup.find_all('a'))
        external_anchors = sum(
            1 for a in soup.find_all('a')
            if urlparse(a.get('href')).netloc != domain or a.get('href') in ['#', '']
        )
        if total_anchors == 0:
            return -1
        percent_external = (external_anchors / total_anchors) * 100
        if percent_external < 31:
            return 1
        elif percent_external <= 67:
            return 0
        else:
            return -1
    except:
        return 1

def calculate_meta_script_link(soup, domain):
    try:
        total_tags = len(soup.find_all(['meta', 'script', 'link']))
        external_tags = sum(
            1 for tag in soup.find_all(['meta', 'script', 'link'])
            if urlparse(tag.get('href', '')).netloc != domain
        )
        if total_tags == 0:
            return -1
        percent_external = (external_tags / total_tags) * 100
        if percent_external < 17:
            return 1
        elif percent_external <= 81:
            return 0
        else:
            return -1
    except:
        return 1

def calculate_sfh(soup, domain):
    try:
        forms = soup.find_all('form')
        if any(form.get('action') in ["", "about:blank"] for form in forms):
            return -1
        elif any(urlparse(form.get('action')).netloc != domain for form in forms):
            return 0
        else:
            return 1
    except:
        return 1

def is_submitting_to_email(soup):
    try:
        if any("mailto:" in form.get('action', '') for form in soup.find_all('form')):
            return -1
    except:
        return 1

def extract_hostname_from_whois(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        whois_info = whois.whois(domain)
        hostname = whois_info.domain_name
        
        if isinstance(hostname, list):
            hostname = hostname[0]
        
        return hostname.lower()
    except Exception as e:
        print(f"Error retrieving WHOIS info: {e}")
        return None

def is_abnormal_url(url):
    hostname = extract_hostname_from_whois(url)
    
    if not hostname:
        return -1  # Phishing, as we couldn't retrieve WHOIS info
    
    domain_in_url = url.split("//")[-1].split("/")[0].lower()
    
    if hostname in domain_in_url:
        return 1  # Legitimate
    else:
        return -1  # Phishing

def calculate_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirect_count = len(response.history)
        
        if redirect_count <= 1:
            return 1  # Legitimate
        elif 2 <= redirect_count < 4:
            return 0  # Suspicious
        else:
            return -1  # Phishing
    except Exception as e:
        print(f"Error checking website forwarding: {e}")
        return -1  # Phishing by default if error occurs

def is_status_bar_customized(soup):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for onMouseOver events
        scripts = soup.find_all('script')
        for script in scripts:
            if 'onMouseOver' in script.string:
                return -1  # Phishing
        
        return 1  # Legitimate
    except Exception as e:
        print(f"Error checking status bar customization: {e}")
        return -1  # Phishing by default if error occurs


def is_right_click_disabled(soup):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for right-click disabling event
        scripts = soup.find_all('script')
        for script in scripts:
            if 'event.button==2' in script.string:
                return -1  # Phishing
        
        return 1  # Legitimate
    except Exception as e:
        print(f"Error checking right click disabled: {e}")
        return -1  # Phishing by default if error occurs

def is_using_pop_up_window(soup):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        scripts = soup.find_all('script')
        for script in scripts:
            if 'window.open' in script.string:
                if '<input' in script.string and 'type="text"' in script.string:
                    return -1  # Phishing

        return 1  # Legitimate
    except Exception as e:
        print(f"Error checking pop-up with text fields: {e}")
        return -1  # Phishing by default if error occurs


def has_iframe_redirection(soup):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            if 'frameborder' in iframe.attrs:
                return -1  # Phishing
        
        return 1  # Legitimate
    except Exception as e:
        print(f"Error checking iframe redirection: {e}")
        return -1  # Phishing by default if error occurs

def calculate_age_of_domain(domain):
    try:
        whois_info = whois.whois(domain)
        age = (whois_info.expiration_date - whois_info.creation_date).days / 30
        return -1 if age >= 6 else 1
    except:
        return 1
#################################
def has_dns_record(domain):
    try:
        whois_info = whois.whois(domain)
        return 1 if whois_info else -1
    except:
        return 1

def calculate_website_traffic(domain):
    try:
        alexa_rank = requests.get(f"http://data.alexa.com/data?cli=10&dat=s&url={domain}").text
        rank = re.search(r'<POPULARITY URL=".*" TEXT="(\d+)" SOURCE="panel">', alexa_rank)
        if rank and int(rank.group(1)) < 100000:
            return 1  # Legitimate
        elif rank and int(rank.group(1)) > 100000:
            return 0  # Suspicious
        else:
            return -1  # Phishing
    except:
        return -1

def calculate_page_rank(domain):
    try:
        pagerank = 0.0  # Example: pagerank = get_pagerank(domain)
        return -1 if pagerank < 0.2 else 1
    except:
        return -1

def is_google_indexed(url):
    try:
        google_search = requests.get(f"https://www.google.com/search?q=site:{url}").text
        return 1 if "did not match any documents" not in google_search else -1
    except:
        return -1

def is_link_pointing_to_page(domain):
    try:
        alexa_rank = requests.get(f"http://data.alexa.com/data?cli=10&dat=s&url={domain}").text
        rank = re.search(r'<LINKSIN NUM="(\d+)"/>', alexa_rank)
        if rank:
            if int(rank.group(1)) == 0:
                return -1  # Phishing
            elif int(rank.group(1)) <= 2:
                return 0  # Suspicious
            else:
                return 1  # Legitimate
        else:
            return -1
    except:
        return -1

def calculate_statistical_report(url):
    report_sites = [
        "phishtank.com", "stopbadware.org", "spamhaus.org",
        "fortiguard.com", "malwaredomainlist.com", "dnswl.org"
    ]
    return -1 if any(site in url for site in report_sites) else 1

def extract_features(url):
    domain = urlparse(url).netloc
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    features = {
        'UsingIP': [is_ip_address(domain)],
        'LongURL': [is_long_url(url)],
        'ShortURL': [is_tiny_url(url)],
        'PrefixSuffix-': [has_prefix_suffix(domain)],
        'SubDomains': [count_subdomains(domain)],
        'HTTPS': [is_https(url)],
        'DomainRegLen': [domain_registration_length(domain)],
        'RequestURL': [calculate_request_url(soup, domain)],
        'AnchorURL': [calculate_url_of_anchor(soup, domain)],
        'LinksInScriptTags': [calculate_meta_script_link(soup, domain)],
        'ServerFormHandler': [calculate_sfh(soup, domain)],
        'AbnormalURL': [is_abnormal_url(domain)],
        'AgeofDomain': [calculate_age_of_domain(domain)],
        'DNSRecording': [has_dns_record(domain)],
        'WebsiteTraffic': [calculate_website_traffic(domain)],
        'PageRank': [calculate_page_rank(domain)],
        'GoogleIndex': [is_google_indexed(url)],
        'StatsReport': [calculate_statistical_report(url)]
    }
    for x in features.values():
        if(x[0]==None):
            x[0]=1
    return features