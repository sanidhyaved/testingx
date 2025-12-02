"""
Progressive XSS Training Laboratory
Provides challenges from basic to advanced for AI training
"""

from flask import Flask, request, render_template_string, abort, make_response
import re
import json
from datetime import datetime

app = Flask(__name__)

class XSSChallenge:
    """Base class for XSS challenges"""
    
    def __init__(self, level, name, description, hints, solution_patterns):
        self.level = level
        self.name = name
        self.description = description
        self.hints = hints
        self.solution_patterns = solution_patterns  # Regex patterns that solve this
        self.attempts = 0
        self.successful_bypasses = []
    
    def check_payload(self, payload):
        """Check if payload bypasses the protection"""
        self.attempts += 1
        
        # Check if any solution pattern matches
        for pattern in self.solution_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                self.successful_bypasses.append({
                    'payload': payload,
                    'timestamp': datetime.now().isoformat()
                })
                return True, "Success! Payload executed!"
        
        return False, self._get_block_reason(payload)
    
    def _get_block_reason(self, payload):
        """Override in subclass to provide specific block reason"""
        return "Payload blocked by protection mechanism"
    
    def get_stats(self):
        return {
            'level': self.level,
            'name': self.name,
            'attempts': self.attempts,
            'successes': len(self.successful_bypasses),
            'success_rate': len(self.successful_bypasses) / self.attempts if self.attempts > 0 else 0
        }

class Level1_BasicScriptTag(XSSChallenge):
    """Level 1: Blocks <script> tag only"""
    
    def __init__(self):
        super().__init__(
            level=1,
            name="Basic Script Tag Filter",
            description="Application blocks <script> tags. Find alternative XSS vectors.",
            hints=[
                "Try event handlers like onerror, onload",
                "Consider using <img>, <svg>, <iframe> tags",
                "Event handlers don't need <script> tags"
            ],
            solution_patterns=[
                r'<img[^>]*onerror',
                r'<svg[^>]*onload',
                r'<body[^>]*onload',
                r'<iframe[^>]*onload',
                r'<input[^>]*onfocus',
                r'<marquee[^>]*onstart',
                r'<details[^>]*ontoggle'
            ]
        )
    
    def is_blocked(self, payload):
        if re.search(r'<script', payload, re.IGNORECASE):
            return True, "Blocked: <script> tag detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level2_EventHandlerCase(XSSChallenge):
    """Level 2: Blocks onerror and onload (case sensitive)"""
    
    def __init__(self):
        super().__init__(
            level=2,
            name="Case-Sensitive Event Handler Filter",
            description="Blocks 'onerror' and 'onload' (lowercase only). Use case variation.",
            hints=[
                "WAFs are often case-sensitive",
                "Try OnError, OnLoad, ONERROR, etc.",
                "Mix upper and lower case"
            ],
            solution_patterns=[
                r'<img[^>]*(OnError|OnErRoR|ONERROR|oNerRor)',
                r'<svg[^>]*(OnLoad|OnLoAd|ONLOAD|oNloAd)',
                r'<body[^>]*(OnLoad|ONLOAD)'
            ]
        )
    
    def is_blocked(self, payload):
        if re.search(r'onerror|onload', payload):  # Lowercase only
            return True, "Blocked: 'onerror' or 'onload' detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level3_SpaceInsertion(XSSChallenge):
    """Level 3: Blocks onerror= pattern"""
    
    def __init__(self):
        super().__init__(
            level=3,
            name="Attribute Pattern Filter",
            description="Blocks 'onerror=' pattern. Break it with spaces.",
            hints=[
                "Add space between attribute and equals",
                "Try: onerror =",
                "Or: on error="
            ],
            solution_patterns=[
                r'onerror\s+=',
                r'on\s+error\s*=',
                r'onload\s+=',
                r'on\s+load\s*='
            ]
        )
    
    def is_blocked(self, payload):
        if re.search(r'onerror=|onload=', payload, re.IGNORECASE):
            return True, "Blocked: 'onerror=' or 'onload=' pattern detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level4_AlternativeHandlers(XSSChallenge):
    """Level 4: Blocks common event handlers"""
    
    def __init__(self):
        super().__init__(
            level=4,
            name="Common Event Handler Blacklist",
            description="Blocks onerror, onload, onclick. Find rare event handlers.",
            hints=[
                "Try uncommon handlers: onmouseover, onanimationend",
                "Consider: ontoggle, onstart, onwheel",
                "HTML5 has many new event handlers"
            ],
            solution_patterns=[
                r'onmouseover',
                r'onmousemove',
                r'onanimationend',
                r'onanimationstart',
                r'ontoggle',
                r'onstart',
                r'onwheel',
                r'onfocus.*autofocus',
                r'oninput',
                r'onpointerover'
            ]
        )
    
    def is_blocked(self, payload):
        common_handlers = r'onerror|onload|onclick|onmousedown|onmouseup'
        if re.search(common_handlers, payload, re.IGNORECASE):
            return True, f"Blocked: Common event handler detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level5_TagBlacklist(XSSChallenge):
    """Level 5: Blocks img, svg, script, iframe"""
    
    def __init__(self):
        super().__init__(
            level=5,
            name="Tag Blacklist",
            description="Blocks img, svg, script, iframe tags. Find alternative tags.",
            hints=[
                "Try: <marquee>, <details>, <object>, <embed>",
                "Consider: <input>, <form>, <body>",
                "Many HTML tags support event handlers"
            ],
            solution_patterns=[
                r'<marquee[^>]*onstart',
                r'<details[^>]*ontoggle',
                r'<object[^>]*data',
                r'<embed[^>]*src',
                r'<input[^>]*onfocus.*autofocus',
                r'<body[^>]*onload',
                r'<form[^>]*onsubmit'
            ]
        )
    
    def is_blocked(self, payload):
        blocked_tags = r'<(img|svg|script|iframe)'
        if re.search(blocked_tags, payload, re.IGNORECASE):
            return True, "Blocked: img/svg/script/iframe tag detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level6_SelfClosingBypass(XSSChallenge):
    """Level 6: Blocks <tag> but not <tag/>"""
    
    def __init__(self):
        super().__init__(
            level=6,
            name="Self-Closing Tag Bypass",
            description="Filter misses self-closing tags. Use / in tags.",
            hints=[
                "Try: <svg/onload=alert(1)>",
                "Or: <img/src=x/onerror=alert(1)>",
                "Self-closing syntax can bypass regex"
            ],
            solution_patterns=[
                r'<svg/[^>]*onload',
                r'<img/[^>]*onerror',
                r'</?\w+/[^>]*on\w+'
            ]
        )
    
    def is_blocked(self, payload):
        # Blocks normal tags but misses self-closing
        if re.search(r'<(svg|img)\s+', payload, re.IGNORECASE):
            return True, "Blocked: svg/img tag with space detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level7_EncodingBypass(XSSChallenge):
    """Level 7: Blocks 'alert' string"""
    
    def __init__(self):
        super().__init__(
            level=7,
            name="String Blacklist (alert blocked)",
            description="The word 'alert' is blocked. Use encoding or alternatives.",
            hints=[
                "Try: alert`1` with backticks",
                "Or: al\\u0065rt(1) with unicode",
                "Or: String.fromCharCode(...)",
                "Or: eval(atob('...'))"
            ],
            solution_patterns=[
                r'alert`',
                r'al\\u0065rt',
                r'String\.fromCharCode',
                r'eval\(',
                r'atob\(',
                r'\[\'alert\'\]',
                r'window\[\'alert\'\]',
                r'prompt\(',
                r'confirm\('
            ]
        )
    
    def is_blocked(self, payload):
        if re.search(r'alert\(', payload, re.IGNORECASE):
            return True, "Blocked: 'alert' function detected"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute"

class Level8_CSPBypass(XSSChallenge):
    """Level 8: Content Security Policy"""
    
    def __init__(self):
        super().__init__(
            level=8,
            name="CSP: script-src 'self'",
            description="CSP blocks inline scripts. Must use existing scripts or attributes.",
            hints=[
                "Inline <script> won't work due to CSP",
                "Event handlers still work (not blocked by this CSP)",
                "Try: <img src=x onerror=location='javascript:alert(1)'>",
                "Or find existing vulnerable scripts on page"
            ],
            solution_patterns=[
                r'<img[^>]*onerror[^>]*location',
                r'<svg[^>]*onload[^>]*location',
                r'href\s*=\s*["\']javascript:',
                r'<a[^>]*href.*javascript:'
            ]
        )
        self.csp = "script-src 'self'"
    
    def is_blocked(self, payload):
        # CSP blocks inline <script>
        if re.search(r'<script', payload, re.IGNORECASE):
            return True, f"Blocked by CSP: {self.csp}"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't execute or blocked by CSP"

class Level9_ContextAware(XSSChallenge):
    """Level 9: Context-based (inside JavaScript)"""
    
    def __init__(self):
        super().__init__(
            level=9,
            name="JavaScript Context XSS",
            description="Input reflected inside <script>var x = 'INPUT';</script>",
            hints=[
                "Close the string and add your code",
                "Try: '; alert(1); //",
                "Or: '; alert(1); var x='",
                "Comment out rest with //"
            ],
            solution_patterns=[
                r"';\s*alert\(",
                r"';\s*prompt\(",
                r"'\s*\+\s*alert\(",
                r"'.*//",
                r"</script><script>alert"
            ]
        )
    
    def is_blocked(self, payload):
        # Simple check - blocks obvious HTML
        if '<' in payload or '>' in payload:
            return True, "Blocked: HTML tags not allowed in JS context"
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't break out of JavaScript context"

class Level10_WAFEvasion(XSSChallenge):
    """Level 10: Advanced WAF with multiple rules"""
    
    def __init__(self):
        super().__init__(
            level=10,
            name="Advanced WAF Evasion",
            description="Multiple protections: tag blacklist, event handler filters, keyword blocking",
            hints=[
                "Combine multiple bypass techniques",
                "Try: <marquee onstart=eval(atob('YWxlcnQoMSk='))>",
                "Use encoding + rare handlers + alternative tags",
                "Think creatively - combine all previous techniques"
            ],
            solution_patterns=[
                r'<marquee[^>]*onstart[^>]*eval',
                r'<details[^>]*ontoggle[^>]*eval',
                r'<marquee[^>]*onstart[^>]*atob',
                r'<input[^>]*onfocus[^>]*eval.*autofocus',
                r'<form[^>]*onsubmit[^>]*return.*false'
            ]
        )
    
    def is_blocked(self, payload):
        # Multiple rules
        blocked_tags = r'<(img|svg|script|iframe|body|object|embed)'
        common_handlers = r'onerror\s*=|onload\s*=|onclick\s*='
        blocked_functions = r'alert\(|prompt\(|confirm\('
        
        if re.search(blocked_tags, payload, re.IGNORECASE):
            return True, "WAF: Blocked tag detected"
        if re.search(common_handlers, payload, re.IGNORECASE):
            return True, "WAF: Common event handler detected"
        if re.search(blocked_functions, payload):
            return True, "WAF: Blocked function detected"
        
        return False, None
    
    def _get_block_reason(self, payload):
        blocked, reason = self.is_blocked(payload)
        if blocked:
            return reason
        return "Payload didn't bypass all WAF rules"

# Initialize all challenges
CHALLENGES = {
    1: Level1_BasicScriptTag(),
    2: Level2_EventHandlerCase(),
    3: Level3_SpaceInsertion(),
    4: Level4_AlternativeHandlers(),
    5: Level5_TagBlacklist(),
    6: Level6_SelfClosingBypass(),
    7: Level7_EncodingBypass(),
    8: Level8_CSPBypass(),
    9: Level9_ContextAware(),
    10: Level10_WAFEvasion(),
}

@app.route('/')
def index():
    """Show all challenges"""
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Training Laboratory</title>
        <style>
            body { 
                font-family: 'Segoe UI', Arial; 
                max-width: 1200px; 
                margin: 0 auto;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            h1 {
                color: #667eea;
                text-align: center;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
            }
            .challenge-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            .challenge-card {
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                padding: 20px;
                transition: all 0.3s;
                cursor: pointer;
            }
            .challenge-card:hover {
                border-color: #667eea;
                transform: translateY(-5px);
                box-shadow: 0 5px 20px rgba(102, 126, 234, 0.3);
            }
            .level-badge {
                display: inline-block;
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: bold;
                font-size: 14px;
                margin-bottom: 10px;
            }
            .level-easy { background: #4caf50; color: white; }
            .level-medium { background: #ff9800; color: white; }
            .level-hard { background: #f44336; color: white; }
            .challenge-name {
                font-size: 18px;
                font-weight: bold;
                color: #333;
                margin: 10px 0;
            }
            .challenge-desc {
                color: #666;
                font-size: 14px;
                line-height: 1.6;
            }
            .stats {
                margin-top: 15px;
                padding-top: 15px;
                border-top: 1px solid #e0e0e0;
                font-size: 13px;
                color: #999;
            }
            .api-info {
                background: #e3f2fd;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 4px solid #2196f3;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎓 XSS Training Laboratory</h1>
            <p class="subtitle">Progressive challenges for training your AI bypass model</p>
            
            <div class="api-info">
                <strong>📡 API Endpoints for Training:</strong><br>
                <code>GET /challenge/{level}?payload=YOUR_XSS</code> - Test a payload<br>
                <code>GET /challenge/{level}/hints</code> - Get hints<br>
                <code>GET /stats</code> - Get all challenge statistics
            </div>
            
            <div class="challenge-grid">
                {% for level, challenge in challenges.items() %}
                <div class="challenge-card" onclick="location.href='/challenge/{{ level }}'">
                    <span class="level-badge {{ 'level-easy' if level <= 3 else 'level-medium' if level <= 7 else 'level-hard' }}">
                        Level {{ level }}
                    </span>
                    <div class="challenge-name">{{ challenge.name }}</div>
                    <div class="challenge-desc">{{ challenge.description }}</div>
                    <div class="stats">
                        Attempts: {{ challenge.attempts }} | 
                        Successes: {{ challenge.successes }} |
                        Rate: {{ "%.1f"|format(challenge.success_rate * 100) }}%
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, challenges={
        level: {
            'name': ch.name,
            'description': ch.description,
            'attempts': ch.attempts,
            'successes': len(ch.successful_bypasses),
            'success_rate': len(ch.successful_bypasses) / ch.attempts if ch.attempts > 0 else 0
        }
        for level, ch in CHALLENGES.items()
    })

@app.route('/challenge/<int:level>')
def challenge_page(level):
    """Individual challenge page"""
    if level not in CHALLENGES:
        abort(404)
    
    challenge = CHALLENGES[level]
    payload = request.args.get('payload', '')
    result = None
    
    if payload:
        success, message = challenge.check_payload(payload)
        result = {
            'success': success,
            'message': message,
            'payload': payload
        }
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level {{ level }} - {{ challenge.name }}</title>
        <style>
            body { 
                font-family: Arial; 
                max-width: 900px; 
                margin: 30px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .level-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }
            .test-area {
                background: #f9f9f9;
                padding: 20px;
                border-radius: 5px;
                margin: 20px 0;
            }
            input[type="text"] {
                width: 100%;
                padding: 15px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-family: monospace;
                font-size: 14px;
            }
            button {
                padding: 15px 40px;
                background: #667eea;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 10px;
            }
            button:hover { background: #5568d3; }
            .result {
                margin-top: 20px;
                padding: 20px;
                border-radius: 5px;
            }
            .success {
                background: #d4edda;
                border-left: 4px solid #28a745;
                color: #155724;
            }
            .failure {
                background: #f8d7da;
                border-left: 4px solid #dc3545;
                color: #721c24;
            }
            .hints {
                background: #fff3cd;
                padding: 20px;
                border-radius: 5px;
                border-left: 4px solid #ffc107;
            }
            .hint-item {
                margin: 10px 0;
                padding-left: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>Level {{ level }}: {{ challenge.name }}</h1>
                <p>{{ challenge.description }}</p>
            </div>
            
            <div class="test-area">
                <h3>🎯 Test Your Payload:</h3>
                <form action="/challenge/{{ level }}" method="GET">
                    <input type="text" name="payload" placeholder="Enter your XSS payload..." 
                           value="{{ payload if payload else '' }}" autofocus>
                    <button type="submit">Test Payload</button>
                </form>
            </div>
            
            {% if result %}
            <div class="result {{ 'success' if result.success else 'failure' }}">
                <strong>{{ '✅ SUCCESS!' if result.success else '❌ BLOCKED' }}</strong><br>
                {{ result.message }}<br>
                <code>{{ result.payload }}</code>
            </div>
            {% endif %}
            
            <div class="hints">
                <h3>💡 Hints:</h3>
                {% for hint in challenge.hints %}
                <div class="hint-item">{{ loop.index }}. {{ hint }}</div>
                {% endfor %}
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
                <a href="/" style="color: #667eea; text-decoration: none;">← Back to All Challenges</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(
        template, 
        level=level, 
        challenge=challenge, 
        payload=payload,
        result=result
    )

@app.route('/challenge/<int:level>/hints')
def get_hints(level):
    """API endpoint for hints"""
    if level not in CHALLENGES:
        return {"error": "Challenge not found"}, 404
    
    challenge = CHALLENGES[level]
    return {
        'level': level,
        'name': challenge.name,
        'description': challenge.description,
        'hints': challenge.hints
    }

@app.route('/stats')
def get_stats():
    """API endpoint for all statistics"""
    stats = {}
    for level, challenge in CHALLENGES.items():
        stats[level] = challenge.get_stats()
        stats[level]['successful_payloads'] = challenge.successful_bypasses
    return stats

if __name__ == '__main__':
    print("="*70)
    print("🎓 XSS TRAINING LABORATORY")
    print("="*70)
    print("[*] Training Environment: ACTIVE")
    print("[*] Levels Available: 10 (Basic → Advanced)")
    print("[*] Access: http://localhost:8080")
    print("[*] API: http://localhost:8080/stats")
    print("="*70)
    print("\n[💡] This lab is designed for training AI models")
    print("[💡] Each level teaches different bypass techniques")
    print("[💡] Statistics are tracked for model improvement\n")
    app.run(host='0.0.0.0', port=8080, debug=True)