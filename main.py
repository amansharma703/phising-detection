import gradio as gr
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import whois
import requests
from datetime import datetime
import urllib.request
from bs4 import BeautifulSoup
import ipaddress
import pandas as pd

# Load the pre-trained Random Forest model
model = joblib.load('my_random_forest.joblib')

# Load the CSV files
legitimate_df = pd.read_csv('legitimate.csv')
phishing_df = pd.read_csv('phishing.csv')

def extract_features_from_url(url):
    print("\n" + "="*50)
    print(f"[Analysis] Starting URL analysis for: {url}")
    print("="*50)
    features = []
    
    # 1. Domain of URL
    domain = getDomain(url)
    features.append(domain)
    print("\n[1. Domain]")
    print(f"Extracted domain: {domain}")
    
    # 2. IP address in URL
    ip_feature = havingIP(url)
    features.append(ip_feature)
    print("\n[2. IP Address Check]")
    print(f"Has IP address: {'Yes' if ip_feature == 1 else 'No'}")
    
    # 3. @ symbol in URL
    at_symbol = haveAtSign(url)
    features.append(at_symbol)
    print("\n[3. @ Symbol Check]")
    print(f"Contains @ symbol: {'Yes' if at_symbol == 1 else 'No'}")
    
    # 4. Length of URL
    length = getLength(url)
    features.append(length)
    print("\n[4. URL Length]")
    print(f"URL length suspicious: {'Yes' if length == 1 else 'No'} (threshold: 54 characters)")
    
    # 5. Depth of URL
    depth = getDepth(url)
    features.append(depth)
    print("\n[5. URL Depth]")
    print(f"Directory depth: {depth}")
    
    # 6-9. Other URL features
    redirect = redirection(url)
    https = httpDomain(url)
    tiny = tinyURL(url)
    prefix_suffix = prefixSuffix(url)
    
    features.extend([redirect, https, tiny, prefix_suffix])
    print("\n[6-9. URL Characteristics]")
    print(f"Double slash redirection: {'Yes' if redirect == 1 else 'No'}")
    print(f"HTTPS in domain name: {'Yes' if https == 1 else 'No'}")
    print(f"Using URL shortener: {'Yes' if tiny == 1 else 'No'}")
    print(f"Has prefix/suffix (-): {'Yes' if prefix_suffix == 1 else 'No'}")
    
    # 10-13. Domain Based Features
    print("\n[10-13. Domain Analysis]")
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        print("✓ WHOIS lookup successful")
    except:
        dns = 1
        print("✗ WHOIS lookup failed")

    features.append(dns)
    
    traffic = web_traffic(url)
    age = 1 if dns == 1 else domainAge(domain_name)
    end = 1 if dns == 1 else domainEnd(domain_name)
    
    features.extend([traffic, age, end])
    print(f"DNS record exists: {'No' if dns == 1 else 'Yes'}")
    print(f"Web traffic: {'Low' if traffic == 1 else 'High'}")
    print(f"Domain age suspicious: {'Yes' if age == 1 else 'No'}")
    print(f"Domain expiry suspicious: {'Yes' if end == 1 else 'No'}")
    
    # 14-17. HTML & Javascript based Features
    print("\n[14-17. Page Content Analysis]")
    try:
        response = requests.get(url)
        print("✓ Successfully retrieved webpage")
    except:
        response = ""
        print("✗ Failed to retrieve webpage")
        
    iframe_feature = iframe(response)
    mouse_over = mouseOver(response)
    right_click = rightClick(response)
    forwarding_feature = forwarding(response)
    
    features.extend([iframe_feature, mouse_over, right_click, forwarding_feature])
    print(f"iFrame present: {'Yes' if iframe_feature == 1 else 'No'}")
    print(f"Mouse over effects: {'Yes' if mouse_over == 1 else 'No'}")
    print(f"Right click disabled: {'Yes' if right_click == 1 else 'No'}")
    print(f"Page forwarding: {'Yes' if forwarding_feature == 1 else 'No'}")
    
    # Remove the domain name from features (first element)
    final_features = features[1:]
    print("\n[Feature Summary]")
    print(f"Total features extracted: {len(final_features)}")
    print("Feature vector:", final_features)
    print("="*50)
    return final_features

# Helper functions from the notebook
def getDomain(url):
    """Extract domain from URL"""
    try:
        # Add http:// if no protocol specified
        if not url.startswith('http'):
            url = 'http://' + url
        
        # Parse URL and get netloc (domain)
        domain = urlparse(url).netloc
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain.replace("www.", "")
            
        # Handle empty domain
        if not domain:
            return url  # Return original URL if parsing fails
            
        print(f"[Domain Extraction] Original URL: {url} -> Domain: {domain}")
        return domain
        
    except Exception as e:
        print(f"[Domain Extraction Error] {str(e)}")
        return url  # Return original URL if parsing fails

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth

def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        return 1 if pos > 7 else 0
    return 0

def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                    r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match = re.search(shortening_services, url)
    return 1 if match else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        return 1 if int(rank) < 100000 else 0
    except:
        return 1

def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if isinstance(creation_date, str) or isinstance(expiration_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        return 1 if ((ageofdomain/30) < 6) else 0

def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 0 if ((end/30) < 6) else 1

def iframe(response):
    if response == "":
        return 1
    else:
        return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

def mouseOver(response):
    if response == "":
        return 1
    else:
        return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def rightClick(response):
    if response == "":
        return 1
    else:
        return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

def forwarding(response):
    if response == "":
        return 1
    else:
        return 0 if len(response.history) <= 2 else 1

def check_domain_in_database(domain):
    """Check if domain exists in our legitimate or phishing databases"""
    print("\n[Database Check]")
    print(f"Checking domain: {domain}")
    
    # Check legitimate domains
    if domain in legitimate_df['Domain'].values:
        print("✓ Domain found in legitimate database")
        return 0  # Real URL
    
    # Check phishing domains
    if domain in phishing_df['Domain'].values:
        print("✗ Domain found in phishing database")
        return 1  # Fake URL
    
    print("! Domain not found in database, performing full analysis")
    return None

def predict_url_nature(url):
    try:
        print("\n[Starting URL Analysis]")
        print(f"URL to analyze: {url}")
        
        # First check if domain is in our database
        domain = getDomain(url)
        print(f"Extracted domain: {domain}")
        db_result = check_domain_in_database(domain)
        
        if db_result is not None:
            result = "Real URL" if db_result == 0 else "Fake URL"
            print(f"\n[Quick Result]")
            print(f"Classification: {result} (from database)")
            print("="*50)
            return result
        
        # If not in database, perform full feature extraction
        features = extract_features_from_url(url)
        
        # Make prediction
        prediction = model.predict([features])[0]
        result = "Real URL" if prediction == 0 else "Fake URL"
        print(f"\n[Final Prediction]")
        print(f"Prediction value: {prediction}")
        print(f"Classification: {result}")
        print("="*50)
        
        return result
    except Exception as e:
        error_msg = f"Error processing URL: {str(e)}"
        print(f"\n[ERROR] {error_msg}")
        print("="*50)
        return error_msg

# Create a Gradio interface with improved styling
interface = gr.Interface(
    fn=predict_url_nature,
    inputs=gr.Textbox(
        label="URL Input",
        placeholder="Enter a URL to check...",
        lines=1
    ),
    outputs=gr.Textbox(label="Prediction Result"),
    title="URL Phishing Detection",
    description="Enter a URL to check if it's real or fake.",
    theme="default",
    examples=[
        ["https://www.google.com"],
        ["http://suspicious-site.com"]
    ]
)

if __name__ == "__main__":
    # Add debug=True for auto-reloading
    interface.launch(debug=True)
