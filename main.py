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

# Load the pre-trained Random Forest model
model = joblib.load('my_random_forest.joblib')

def extract_features_from_url(url):
    features = []
    
    # 1. Domain of URL
    domain = getDomain(url)
    features.append(domain)
    
    # 2. IP address in URL
    features.append(havingIP(url))
    
    # 3. @ symbol in URL
    features.append(haveAtSign(url))
    
    # 4. Length of URL
    features.append(getLength(url))
    
    # 5. Depth of URL
    features.append(getDepth(url))
    
    # 6. Redirection "//" in URL
    features.append(redirection(url))
    
    # 7. "http/https" in Domain name
    features.append(httpDomain(url))
    
    # 8. Using URL Shortening Services
    features.append(tinyURL(url))
    
    # 9. Prefix or Suffix "-" in Domain
    features.append(prefixSuffix(url))
    
    # 10-13. Domain Based Features
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns)  # 10. DNS Record
    features.append(web_traffic(url))  # 11. Web Traffic
    features.append(1 if dns == 1 else domainAge(domain_name))  # 12. Domain Age
    features.append(1 if dns == 1 else domainEnd(domain_name))  # 13. End Period of Domain
    
    # 14-17. HTML & Javascript based Features
    try:
        response = requests.get(url)
    except:
        response = ""
        
    features.append(iframe(response))  # 14. IFrame Redirection
    features.append(mouseOver(response))  # 15. Status Bar Customization
    features.append(rightClick(response))  # 16. Disabling Right Click
    features.append(forwarding(response))  # 17. Website Forwarding
    
    # Remove the domain name from features (first element) as it's not numerical
    return features[1:]

# Helper functions from the notebook
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

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

def predict_url_nature(url):
    try:
        # Extract features from the URL
        features = extract_features_from_url(url)
        
        # Make prediction using the Random Forest model
        prediction = model.predict([features])[0]
        
        # Return the prediction result
        return "Real URL" if prediction == 0 else "Fake URL"
    except Exception as e:
        return f"Error processing URL: {str(e)}"

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
    interface.launch(share=True)
