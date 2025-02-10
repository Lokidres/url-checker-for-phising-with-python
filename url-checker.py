import requests
import whois
from datetime import datetime
import re
from urllib.parse import urlparse

def check_https(url):
    """Check if URL uses HTTPS"""
    try:
        response = requests.get(url, timeout=5)
        return response.url.startswith('https')
    except:
        return False

def check_domain_age(domain):
    """Check domain age in days"""
    try:
        details = whois.whois(domain)
        creation_date = details.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except:
        return 0

def check_sensitive_keywords(url):
    """Check for suspicious keywords"""
    keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'banking']
    return any(re.search(fr'\b{kw}\b', url, re.I) for kw in keywords)

def check_short_url(url):
    """Check for URL shorteners"""
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
    return any(s in url for s in shorteners)

def analyze_url(url):
    """Run all checks and generate risk score"""
    score = 0
    warnings = []
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # HTTPS Check
    if not check_https(url):
        score += 30
        warnings.append("⚠️ Does not use HTTPS")
    
    # Domain Age
    domain_age = check_domain_age(domain)
    if domain_age < 365:
        score += 20
        warnings.append(f"⚠️ New domain ({domain_age} days old)")
    
    # Sensitive Keywords
    if check_sensitive_keywords(url):
        score += 25
        warnings.append("⚠️ Contains suspicious keywords")
    
    # URL Shortener
    if check_short_url(url):
        score += 25
        warnings.append("⚠️ Uses URL shortening service")
    
    # Risk Evaluation
    risk_level = "Low Risk" if score < 35 else \
               "Medium Risk" if score < 65 else \
               "High Risk"
    
    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "warnings": warnings
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python phishing_url_checker.py <URL>")
        sys.exit(1)
    
    result = analyze_url(sys.argv[1])
    print(f"\n🔍 Analysis Results: {result['url']}")
    print(f"📊 Risk Score: {result['risk_score']}/100")
    print(f"🚨 Risk Level: {result['risk_level']}")
    if result['warnings']:
        print("\n🔔 Warnings:")
        for warn in result['warnings']:
            print(f" - {warn}")
    print("\nℹ️ This tool does not provide absolute certainty. Always take additional security measures.")