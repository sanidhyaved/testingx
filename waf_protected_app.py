"""
WAF-Protected Test Application
Simulates a real Web Application Firewall with XSS protections
"""

from flask import Flask, request, render_template_string, abort
import re

app = Flask(__name__)

# WAF Configuration
class SimpleWAF:
    """Simulates a Web Application Firewall with various XSS protections"""
    
    def __init__(self, strictness='medium'):
        self.strictness = strictness
        self.blocked_count = 0
        
        # Different rule sets based on strictness
        if strictness == 'low':
            self.rules = self._get_basic_rules()
        elif strictness == 'medium':
            self.rules = self._get_medium_rules()
        else:  # high
            self.rules = self._get_strict_rules()
    
    def _get_basic_rules(self):
        """Basic XSS blocking - Easy to bypass"""
        return [
            (r'<script>', 'Script tag detected'),
            (r'javascript:', 'JavaScript protocol detected'),
        ]
    
    def _get_medium_rules(self):
        """Medium protection - Moderate difficulty"""
        return [
            (r'<script[^>]*>', 'Script tag detected', re.IGNORECASE),
            (r'javascript:', 'JavaScript protocol detected', re.IGNORECASE),
            (r'onerror\s*=', 'Event handler detected', re.IGNORECASE),
            (r'onload\s*=', 'Event handler detected', re.IGNORECASE),
            (r'<iframe', 'Iframe tag detected', re.IGNORECASE),
            (r'eval\(', 'Eval detected', re.IGNORECASE),
        ]
    
    def _get_strict_rules(self):
        """Strict protection - Hard to bypass"""
        return [
            (r'<script[^>]*>', 'Script tag blocked', re.IGNORECASE),
            (r'javascript:', 'JavaScript protocol blocked', re.IGNORECASE),
            (r'on\w+\s*=', 'Event handler blocked', re.IGNORECASE),
            (r'<iframe', 'Iframe blocked', re.IGNORECASE),
            (r'<object', 'Object blocked', re.IGNORECASE),
            (r'<embed', 'Embed blocked', re.IGNORECASE),
            (r'<svg', 'SVG blocked', re.IGNORECASE),
            (r'eval\(', 'Eval blocked', re.IGNORECASE),
            (r'alert\(', 'Alert blocked', re.IGNORECASE),
            (r'prompt\(', 'Prompt blocked', re.IGNORECASE),
            (r'confirm\(', 'Confirm blocked', re.IGNORECASE),
            (r'<img[^>]*>', 'Image tag blocked', re.IGNORECASE),
            (r'src\s*=', 'Src attribute blocked', re.IGNORECASE),
            (r'href\s*=\s*["\']?javascript:', 'JavaScript href blocked', re.IGNORECASE),
        ]
    
    def check_payload(self, payload):
        """Check if payload violates WAF rules"""
        if not payload:
            return True, None
        
        for rule in self.rules:
            if len(rule) == 2:
                pattern, message = rule
                flags = 0
            else:
                pattern, message, flags = rule
            
            if re.search(pattern, payload, flags):
                self.blocked_count += 1
                return False, message
        
        return True, None
    
    def get_stats(self):
        return {
            'blocked_count': self.blocked_count,
            'strictness': self.strictness
        }

# Initialize WAF with medium strictness
waf = SimpleWAF(strictness='medium')

# WAF Middleware
@app.before_request
def waf_check():
    """Check all incoming requests against WAF rules"""
    
    # Check all query parameters
    for key, value in request.args.items():
        allowed, reason = waf.check_payload(value)
        if not allowed:
            print(f"[WAF] BLOCKED: {value[:50]} - Reason: {reason}")
            return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>403 Forbidden</title>
                    <style>
                        body { 
                            font-family: Arial; 
                            max-width: 600px; 
                            margin: 100px auto; 
                            text-align: center;
                            background: #f5f5f5;
                        }
                        .error-box {
                            background: white;
                            padding: 40px;
                            border-radius: 10px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }
                        h1 { color: #d32f2f; }
                        .waf-badge {
                            background: #1976d2;
                            color: white;
                            padding: 5px 15px;
                            border-radius: 20px;
                            display: inline-block;
                            margin: 20px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="error-box">
                        <h1>🛡️ 403 Forbidden</h1>
                        <div class="waf-badge">Protected by SimpleWAF</div>
                        <p><strong>Your request was blocked by our Web Application Firewall</strong></p>
                        <p>Reason: {{ reason }}</p>
                        <p style="color: #666; font-size: 14px; margin-top: 30px;">
                            If you believe this is an error, please contact support.
                        </p>
                    </div>
                </body>
                </html>
            """, reason=reason), 403
    
    # Check POST data
    for key, value in request.form.items():
        allowed, reason = waf.check_payload(value)
        if not allowed:
            print(f"[WAF] BLOCKED: {value[:50]} - Reason: {reason}")
            return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head><title>403 Forbidden</title></head>
                <body>
                    <h1>403 Forbidden</h1>
                    <p>WAF Blocked: {{ reason }}</p>
                </body>
                </html>
            """, reason=reason), 403

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF-Protected Test Application</title>
    <style>
        body { 
            font-family: Arial; 
            max-width: 900px; 
            margin: 30px auto;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .waf-status {
            background: #1976d2;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .search-box { 
            padding: 20px; 
            background: #f9f9f9;
            border-radius: 5px;
            margin: 20px 0;
        }
        input { 
            padding: 10px; 
            width: 60%; 
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button { 
            padding: 10px 30px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #1565c0;
        }
        .results {
            margin-top: 20px;
            padding: 20px;
            background: #e3f2fd;
            border-left: 4px solid #1976d2;
        }
        .stats {
            background: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .vulnerability-note {
            background: #ffebee;
            padding: 15px;
            border-left: 4px solid #d32f2f;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WAF-Protected Application</h1>
        
        <div class="waf-status">
            <strong>🔒 WAF Status:</strong> ACTIVE ({{ waf_strictness.upper() }} Mode)<br>
            <strong>Blocks:</strong> {{ blocked_count }} attacks prevented
        </div>
        
        <div class="vulnerability-note">
            <strong>⚠️ Note:</strong> This application is intentionally vulnerable to XSS,
            but protected by a Web Application Firewall. Try bypassing it!
        </div>
        
        <div class="search-box">
            <h3>Search Function</h3>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Try injecting XSS payloads..." value="{{ query if query else '' }}">
                <button type="submit">Search</button>
            </form>
        </div>
        
        {% if query %}
        <div class="results">
            <h3>Search Results for: {{ query|safe }}</h3>
            <p>No results found for your query.</p>
        </div>
        {% endif %}
        
        <hr style="margin: 30px 0;">
        
        <div class="search-box">
            <h3>User Profile Lookup</h3>
            <form action="/profile" method="GET">
                <input type="text" name="id" placeholder="Enter user ID..." value="">
                <button type="submit">Lookup</button>
            </form>
        </div>
        
        <div class="stats">
            <h4>💡 Challenge:</h4>
            <ul>
                <li>Try common XSS payloads - they'll be blocked</li>
                <li>Use your AI scanner to generate bypass payloads</li>
                <li>See if AI can find creative ways around the WAF</li>
                <li>Current WAF blocks: <code>{{ waf_strictness }}</code> level rules</li>
            </ul>
        </div>
        
        <div style="margin-top: 30px; padding: 20px; background: #f5f5f5; border-radius: 5px;">
            <h4>📊 WAF Rules Active:</h4>
            <p style="font-size: 14px; color: #666;">
                Script tags, JavaScript protocols, common event handlers (onerror, onload), 
                iframes, and eval() are currently being blocked.
            </p>
            <p style="font-size: 12px; color: #999; margin-top: 10px;">
                <strong>Hint:</strong> Look for alternative event handlers, encoding techniques,
                or tag manipulation to bypass the filters!
            </p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    stats = waf.get_stats()
    return render_template_string(
        TEMPLATE, 
        query=None, 
        waf_strictness=stats['strictness'],
        blocked_count=stats['blocked_count']
    )

@app.route('/search')
def search():
    query = request.args.get('q', '')
    stats = waf.get_stats()
    # VULNERABLE: Not sanitizing input (but protected by WAF)
    return render_template_string(
        TEMPLATE, 
        query=query,
        waf_strictness=stats['strictness'],
        blocked_count=stats['blocked_count']
    )

@app.route('/profile')
def profile():
    user_id = request.args.get('id', '1')
    # Another vulnerable endpoint
    template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Profile</title>
        <style>
            body {{ 
                font-family: Arial; 
                max-width: 800px; 
                margin: 50px auto;
                padding: 20px;
            }}
            .profile {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
        </style>
    </head>
    <body>
        <div class="profile">
            <h1>User Profile</h1>
            <script>
                var userId = '{user_id}';
                console.log('Viewing profile: ' + userId);
            </script>
            <p><strong>User ID:</strong> {user_id}</p>
            <p><strong>Status:</strong> Active</p>
            <a href="/">← Back to Home</a>
        </div>
    </body>
    </html>
    """
    return template

@app.route('/admin/waf/config')
def waf_config():
    """Admin endpoint to change WAF strictness"""
    level = request.args.get('level', 'medium')
    
    if level in ['low', 'medium', 'high']:
        global waf
        waf = SimpleWAF(strictness=level)
        return f"""
        <html>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h2>WAF Configuration Updated</h2>
            <p>Strictness level set to: <strong>{level}</strong></p>
            <ul>
                <li><a href="/admin/waf/config?level=low">Set to LOW (easy)</a></li>
                <li><a href="/admin/waf/config?level=medium">Set to MEDIUM (moderate)</a></li>
                <li><a href="/admin/waf/config?level=high">Set to HIGH (hard)</a></li>
            </ul>
            <a href="/">← Back to Home</a>
        </body>
        </html>
        """
    
    return "Invalid level", 400

if __name__ == '__main__':
    print("="*60)
    print("WAF-PROTECTED TEST APPLICATION")
    print("="*60)
    print("[🛡️] Web Application Firewall: ACTIVE")
    print("[📊] Strictness Level: MEDIUM")
    print("[🎯] Challenge: Try to bypass the WAF with XSS!")
    print("[🔗] Running on http://localhost:8080")
    print("[⚙️]  Change WAF level: http://localhost:8080/admin/waf/config?level=low")
    print("="*60)
    app.run(host='0.0.0.0', port=8080, debug=True)