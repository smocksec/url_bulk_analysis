import requests
import base64
import pandas as pd
import json
import domain
import path
from datetime import datetime
import time
import os
from urllib.parse import urlparse
import re
import logging
import xlsxwriter
from tqdm import tqdm  # Debugging Log Library

class URLAnalyzer:
    def __init__(self):
        # Set up logging
        self.setup_logging()
        
        self.logger.info("Initializing URLAnalyzer")
        # sign up for these API keys
        self.vt_api_key = "#Fill The API Key here"
        self.urlscan_api_key = "#Fill The API Key here"
        
        # Initialize results dictionary with new fields
        self.results = {
            'url': [],
            'category': [],
            'reputation_score': [],
            'malicious_flags': [],
            'last_analysis_date': [],
            'references': [],
            'needs_manual_review': [],
            'manual_review_reason': []
        }

        # Define suspicious patterns
        self.suspicious_patterns = {
            'unusual_chars': r'[^\w\-\./:]',  # Unusual characters in URL
            'ip_address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            'suspicious_keywords': [
                'login', 'signin', 'account', 'verify', 'secure', 'banking',
                'update', 'password', 'credential', 'wallet', 'crypto',
                'prize', 'winner', 'free', 'urgent', 'payment'
            ],
            'suspicious_tlds': [
                '.xyz', '.top', '.club', '.online', '.site', '.icu', 
                '.live', '.click', '.work', '.loan'
            ]
        }
        self.logger.info("URLAnalyzer initialized successfully")
    def setup_logging(self):
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        # Set up logging configuration
        log_filename = f'logs/url_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    def categorize_url(self, url):
        categories = []
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
    
    # E-commerce patterns
        if any(keyword in domain + path for keyword in ['shop', 'store', 'buy', 'cart', 'checkout', 'product']):
            categories.append('E-commerce')
    
    # Social media patterns
        if any(platform in domain for platform in ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'youtube']):
            categories.append('Social Media')
    
    # News and media patterns
        if any(keyword in domain for keyword in ['news', 'media', 'blog', 'article']):
            categories.append('News/Media')
    
    # Technology patterns
        if any(keyword in domain + path for keyword in ['tech', 'software', 'download', 'app', 'program']):
            categories.append('Technology')
    
    # Financial services
        if any(keyword in domain + path for keyword in ['bank', 'finance', 'pay', 'money', 'invest']):
            categories.append('Financial')
    
    # Educational content
        if any(keyword in domain for keyword in ['edu', 'learn', 'course', 'study', 'academic']):
            categories.append('Educational')
    
    # Government websites
        if '.gov' in domain or any(keyword in domain for keyword in ['government', 'gov']):
            categories.append('Government')
    
    # Entertainment
        if any(keyword in domain + path for keyword in ['game', 'movie', 'music', 'entertainment', 'play']):
            categories.append('Entertainment')
    
    # Check for potentially malicious indicators
        if any(pattern in domain + path for pattern in [
        'login', 'signin', 'account', 'verify', 'secure', 'update', 'password'
    ]):
            categories.append('Potential Phishing')
    
    # If no specific category is identified
        if not categories:
            categories.append('Other')
    
        return categories

    def check_suspicious_patterns(self, url):
        reasons = []
        parsed_url = urlparse(url)
        url_lower = url.lower()
        
        # Check for unusual characters
        if re.search(self.suspicious_patterns['unusual_chars'], parsed_url.netloc):
            reasons.append("Contains unusual characters")
        
        # Check for IP address instead of domain
        if re.match(self.suspicious_patterns['ip_address'], parsed_url.netloc):
            reasons.append("Uses IP address instead of domain name")
        
        # Check for suspicious keywords
        found_keywords = [keyword for keyword in self.suspicious_patterns['suspicious_keywords'] 
                         if keyword in url_lower]
        if found_keywords:
            reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        
        # Check for suspicious TLDs
        if any(tld in parsed_url.netloc.lower() for tld in self.suspicious_patterns['suspicious_tlds']):
            reasons.append("Uses suspicious TLD")
        
        # Check for extremely long URLs
        if len(url) > 100:
            reasons.append("Unusually long URL")
        
        # Check for multiple subdomains
        subdomain_count = len(parsed_url.netloc.split('.')) - 2
        if subdomain_count > 2:
            reasons.append("Contains multiple subdomains")
        
        # Check for encoded characters
        if '%' in url:
            reasons.append("Contains encoded characters")
            
        return reasons

    def analyze_with_virustotal(self, url):
        self.logger.info(f"Starting VirusTotal analysis for: {url}")
        # Previous VirusTotal analysis code remains the same
        headers = {
            "accept": "application/json",
            "x-apikey": self.vt_api_key
        }
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        self.logger.debug(f"Making API request to VirusTotal for URL: {url}")
        response = requests.get(endpoint, headers=headers)
        
        try:
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                result = response.json()
                self.logger.info(f"VirusTotal analysis successful for: {url}")
                return {
                    'reputation_score': result['data']['attributes']['reputation'],
                    'last_analysis_stats': result['data']['attributes']['last_analysis_stats'],
                    'categories': result['data']['attributes'].get('categories', {}),
                    'total_votes': result['data']['attributes'].get('total_votes', {})
                }
            else:
                self.logger.warning(f"VirusTotal API returned status code {response.status_code} for {url}")

        except Exception as e:
            
            print(f"Error analyzing {url} with VirusTotal: {str(e)}")
        return None

    def determine_manual_review_need(self, url, vt_results, urlscan_results):
        needs_review = False
        review_reasons = []
        
        # Check for suspicious patterns
        pattern_reasons = self.check_suspicious_patterns(url)
        if pattern_reasons:
            needs_review = True
            review_reasons.extend(pattern_reasons)
        
        # Check VirusTotal results
        if vt_results:
            if vt_results['last_analysis_stats'].get('malicious', 0) > 0:
                needs_review = True
                review_reasons.append(f"VirusTotal flagged as malicious: {vt_results['last_analysis_stats']['malicious']} detections")
            
            if vt_results.get('reputation_score', 0) < 0:
                needs_review = True
                review_reasons.append("Negative reputation score on VirusTotal")
            
            # Check community votes if available
            total_votes = vt_results.get('total_votes', {})
            if total_votes.get('malicious', 0) > total_votes.get('harmless', 0):
                needs_review = True
                review_reasons.append("Negative community votes on VirusTotal")
        
        # Check URLScan results if available
        if urlscan_results:
            if urlscan_results.get('verdicts', {}).get('overall', {}).get('malicious', False):
                needs_review = True
                review_reasons.append("URLScan.io flagged as malicious")
        
        return needs_review, review_reasons
    def analyze_with_urlscan(self, url):
        headers = {
            'API-Key': self.urlscan_api_key,
            'Content-Type': 'application/json',
    }
        data = {
            'url': url,
            'visibility': 'public'
    }
    
        try:
        # Submit URL for scanning
            submit_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
            if submit_response.status_code == 200:
                uuid = submit_response.json().get('uuid')
            
            # Wait for scan to complete (usually takes 10-20 seconds)
                time.sleep(10)
            
            # Get the results
                result_url = f'https://urlscan.io/api/v1/result/{uuid}/'
                result_response = requests.get(result_url)
            
                if result_response.status_code == 200:
                    return result_response.json()
            
        except Exception as e:
            print(f"Error analyzing {url} with URLScan.io: {str(e)}")
        return None

    def analyze_urls_from_excel(self, excel_file):
        df = pd.read_excel(excel_file)
        
        for url in df['url']: ##ColumnName
            # Basic categorization
            categories = self.categorize_url(url)
            
            # VirusTotal analysis
            vt_results = self.analyze_with_virustotal(url)
            
            # URLScan analysis
            urlscan_results = self.analyze_with_urlscan(url)
            
            # Determine if manual review is needed
            needs_review, review_reasons = self.determine_manual_review_need(url, vt_results, urlscan_results)
            
            # Compile results
            self.results['url'].append(url)
            self.results['category'].append(categories)
            self.results['needs_manual_review'].append(needs_review)
            self.results['manual_review_reason'].append('; '.join(review_reasons) if review_reasons else 'None')
            
            if vt_results:
                self.results['reputation_score'].append(vt_results['reputation_score'])
                malicious_flags = []
                if vt_results['last_analysis_stats'].get('malicious', 0) > 0:
                    malicious_flags.append('Potential Security Risk')
                self.results['malicious_flags'].append(malicious_flags)
            else:
                self.results['reputation_score'].append(None)
                self.results['malicious_flags'].append([])
            
            self.results['last_analysis_date'].append(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            references = []
            if vt_results:
                references.append(f"VirusTotal: https://www.virustotal.com/gui/url/{url}")
            if urlscan_results:
                references.append(f"URLScan: {urlscan_results.get('task', {}).get('reportURL', '')}")
            self.results['references'].append(references)
            
            # Respect API rate limits
            time.sleep(2)

    def export_results(self, output_file='url_analysis_results_1.xlsx'):
        df = pd.DataFrame(self.results)
        
        # Create a summary of URLs needing manual review
        manual_review_df = df[df['needs_manual_review'] == True][
            ['url', 'category', 'manual_review_reason', 'reputation_score', 'references']
        ]
        
        # Create Excel writer object with multiple sheets
        with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='All Results', index=False)
            manual_review_df.to_excel(writer, sheet_name='Manual Review Required', index=False)
            
            # Highlight suspicious URLs in the manual review sheet
            workbook = writer.book
            worksheet = writer.sheets['Manual Review Required']
            
            # Add formatting
            red_format = workbook.add_format({'bg_color': '#FFC7CE'})
            worksheet.conditional_format('A2:E1000', {
                'type': 'text',
                'criteria': 'containing',
                'value': '',  # This will apply to all non-empty cells
                'format': red_format
            })
        
        print(f"Results exported to {output_file}")
        print(f"Found {len(manual_review_df)} URLs that need manual review")
    
# Usage example
if __name__ == "__main__":
    try:
        analyzer = URLAnalyzer()
        analyzer.analyze_urls_from_excel('list_url.xlsx')
        analyzer.export_results()
    except Exception as e:
        logging.error("Fatal error in main execution", exc_info=True)