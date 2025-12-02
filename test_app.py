"""
Simple vulnerable web application for testing the XSS scanner
WARNING: This is INTENTIONALLY VULNERABLE - only use for testing!
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Basic vulnerable page
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Test Application</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; }
        .search-box { padding: 20px; background: #f0f0f0; }
        input { padding: 10px; width: 300px; }
        button { padding: 10px 20px; }
    </style>
</head>
<body>
    <h1>Test Search Application</h1>
    
    <div class="search-box">
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
    </div>
    
    {% if query %}
    <div style="margin-top: 20px;">
        <h2>Search Results for: {{ query|safe }}</h2>
        <p>No results found.</p>
    </div>
    {% endif %}
    
    <hr>
    
    <h3>Comment Form (Stored XSS Test)</h3>
    <form action="/comment" method="POST">
        <input type="text" name="name" placeholder="Your name"><br><br>
        <textarea name="comment" rows="4" cols="50" placeholder="Your comment"></textarea><br><br>
        <button type="submit">Submit Comment</button>
    </form>
    
    {% if comments %}
    <div style="margin-top: 20px;">
        <h3>Comments:</h3>
        {% for comment in comments %}
        <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
            <strong>{{ comment.name|safe }}</strong>: {{ comment.text|safe }}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
"""

# Store comments in memory (not persistent)
comments = []

@app.route('/')
def index():
    return render_template_string(TEMPLATE, query=None, comments=comments)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: Not sanitizing input
    return render_template_string(TEMPLATE, query=query, comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    name = request.form.get('name', 'Anonymous')
    text = request.form.get('comment', '')
    # VULNERABLE: Storing unsanitized input
    comments.append({'name': name, 'text': text})
    return render_template_string(TEMPLATE, query=None, comments=comments)

@app.route('/profile')
def profile():
    # Another vulnerable endpoint with different context
    user_id = request.args.get('id', '1')
    template = f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h1>User Profile</h1>
        <script>
            var userId = '{user_id}';
            console.log('User ID: ' + userId);
        </script>
        <p>Viewing profile: {user_id}</p>
    </body>
    </html>
    """
    return template

if __name__ == '__main__':
    print("="*60)
    print("VULNERABLE TEST APPLICATION")
    print("="*60)
    print("[!] This application is INTENTIONALLY vulnerable")
    print("[!] Only use for testing your XSS scanner")
    print("[!] Running on http://localhost:8080")
    print("="*60)
    app.run(host='0.0.0.0', port=8080, debug=True)