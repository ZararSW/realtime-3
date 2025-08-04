#!/usr/bin/env python3
"""
Test Flask Application for Cybersecurity Tool Testing
Creates vulnerable endpoints for testing XSS, SQLi, SSRF, IDOR, CSRF, etc.
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import sqlite3
import os
import urllib.request
import subprocess
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'test_secret_key_not_for_production'

# Initialize test database
def init_db():
    """Initialize test database with vulnerable data"""
    conn = sqlite3.connect('test_db.sqlite')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            balance REAL,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Insert test data
    test_users = [
        (1, 'admin', 'admin123', 'admin@test.com', 10000.0, 1),
        (2, 'user1', 'password123', 'user1@test.com', 500.0, 0),
        (3, 'user2', 'qwerty', 'user2@test.com', 750.0, 0),
        (4, 'testuser', 'test123', 'test@test.com', 250.0, 0)
    ]
    
    cursor.executemany(
        'INSERT OR REPLACE INTO users (id, username, password, email, balance, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
        test_users
    )
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Main page with links to vulnerable endpoints"""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cybersecurity Test Application</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .vulnerability { background: #f0f0f0; padding: 20px; margin: 20px 0; border-radius: 5px; }
            .vulnerability h3 { color: #d32f2f; }
            a { color: #1976d2; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>🔒 Cybersecurity Test Application</h1>
        <p>This application contains intentionally vulnerable endpoints for security testing.</p>
        
        <div class="vulnerability">
            <h3>🚨 XSS (Cross-Site Scripting)</h3>
            <p><a href="/xss_reflect">Reflected XSS</a> - Test with: <code>?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
            <p><a href="/xss_stored">Stored XSS</a> - Submit comment with script tags</p>
        </div>
        
        <div class="vulnerability">
            <h3>💉 SQL Injection</h3>
            <p><a href="/sqli_login">Login SQLi</a> - Test with: <code>admin' OR '1'='1</code></p>
            <p><a href="/sqli_search">Search SQLi</a> - Test with: <code>' UNION SELECT username,password FROM users--</code></p>
        </div>
        
        <div class="vulnerability">
            <h3>🌐 SSRF (Server-Side Request Forgery)</h3>
            <p><a href="/ssrf">SSRF Test</a> - Test with: <code>http://169.254.169.254/latest/meta-data/</code></p>
        </div>
        
        <div class="vulnerability">
            <h3>🔑 IDOR (Insecure Direct Object Reference)</h3>
            <p><a href="/profile/1">User Profile</a> - Test with different user IDs</p>
            <p><a href="/admin/users">Admin Panel</a> - Access control bypass</p>
        </div>
        
        <div class="vulnerability">
            <h3>🛡️ CSRF (Cross-Site Request Forgery)</h3>
            <p><a href="/transfer">Money Transfer</a> - Missing CSRF protection</p>
        </div>
        
        <div class="vulnerability">
            <h3>⚡ Command Injection</h3>
            <p><a href="/ping">Ping Tool</a> - Test with: <code>127.0.0.1; whoami</code></p>
        </div>
        
        <div class="vulnerability">
            <h3>📁 LFI (Local File Inclusion)</h3>
            <p><a href="/file?name=test.txt">File Reader</a> - Test with: <code>../../../etc/passwd</code></p>
        </div>
    </body>
    </html>
    ''')

# XSS Vulnerabilities
@app.route('/xss_reflect')
def xss_reflect():
    """Reflected XSS vulnerability"""
    query = request.args.get('q', '')
    return render_template_string(f'''
    <h2>Search Results</h2>
    <p>You searched for: {query}</p>
    <form method="GET">
        <input type="text" name="q" placeholder="Search..." value="{query}">
        <input type="submit" value="Search">
    </form>
    <a href="/">Back to Home</a>
    ''')

@app.route('/xss_stored', methods=['GET', 'POST'])
def xss_stored():
    """Stored XSS vulnerability"""
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # Store comment in session (simulating storage)
        if 'comments' not in session:
            session['comments'] = []
        session['comments'].append(comment)
    
    comments = session.get('comments', [])
    comments_html = ''.join([f'<div class="comment">{comment}</div>' for comment in comments])
    
    return render_template_string(f'''
    <h2>Comment System</h2>
    <form method="POST">
        <textarea name="comment" placeholder="Your comment..."></textarea><br>
        <input type="submit" value="Post Comment">
    </form>
    <div class="comments">
        <h3>Comments:</h3>
        {comments_html}
    </div>
    <a href="/">Back to Home</a>
    ''')

# SQL Injection Vulnerabilities
@app.route('/sqli_login', methods=['GET', 'POST'])
def sqli_login():
    """SQL injection in login form"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Vulnerable query
        conn = sqlite3.connect('test_db.sqlite')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return f"<h2>Login Successful!</h2><p>Welcome {user[1]}!</p><a href='/'>Home</a>"
            else:
                return f"<h2>Login Failed</h2><p>Query executed: {query}</p><a href='/sqli_login'>Try Again</a>"
        except Exception as e:
            conn.close()
            return f"<h2>Database Error</h2><p>Error: {str(e)}</p><p>Query: {query}</p><a href='/sqli_login'>Try Again</a>"
    
    return render_template_string('''
    <h2>Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <input type="submit" value="Login">
    </form>
    <p>Hint: Try SQL injection payloads like <code>admin' OR '1'='1</code></p>
    <a href="/">Back to Home</a>
    ''')

@app.route('/sqli_search')
def sqli_search():
    """SQL injection in search functionality"""
    search = request.args.get('search', '')
    
    if search:
        conn = sqlite3.connect('test_db.sqlite')
        cursor = conn.cursor()
        # Vulnerable query
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search}%'"
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            
            results_html = ''.join([f'<li>{result[0]} - {result[1]}</li>' for result in results])
            return render_template_string(f'''
            <h2>Search Results</h2>
            <p>Query: <code>{query}</code></p>
            <ul>{results_html}</ul>
            <a href="/sqli_search">Search Again</a> | <a href="/">Home</a>
            ''')
        except Exception as e:
            conn.close()
            return f"<h2>Database Error</h2><p>Error: {str(e)}</p><p>Query: {query}</p>"
    
    return render_template_string('''
    <h2>User Search</h2>
    <form method="GET">
        <input type="text" name="search" placeholder="Search users..." required>
        <input type="submit" value="Search">
    </form>
    <p>Hint: Try UNION injection like <code>' UNION SELECT username,password FROM users--</code></p>
    <a href="/">Back to Home</a>
    ''')

# SSRF Vulnerability
@app.route('/ssrf')
def ssrf():
    """Server-Side Request Forgery vulnerability"""
    url = request.args.get('url', '')
    
    if url:
        try:
            # Vulnerable SSRF - no URL validation
            response = urllib.request.urlopen(url, timeout=5)
            content = response.read().decode('utf-8', errors='ignore')
            return render_template_string(f'''
            <h2>URL Content</h2>
            <p>Fetched from: <code>{url}</code></p>
            <pre>{content[:1000]}...</pre>
            <a href="/ssrf">Fetch Another URL</a> | <a href="/">Home</a>
            ''')
        except Exception as e:
            return f"<h2>Error</h2><p>Could not fetch URL: {str(e)}</p><a href='/ssrf'>Try Again</a>"
    
    return render_template_string('''
    <h2>URL Fetcher</h2>
    <form method="GET">
        <input type="url" name="url" placeholder="Enter URL to fetch..." required style="width: 400px;">
        <input type="submit" value="Fetch">
    </form>
    <p>Hint: Try internal URLs like <code>http://169.254.169.254/latest/meta-data/</code></p>
    <a href="/">Back to Home</a>
    ''')

# IDOR Vulnerabilities
@app.route('/profile/<int:user_id>')
def profile(user_id):
    """Insecure Direct Object Reference - user profiles"""
    conn = sqlite3.connect('test_db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, balance FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return render_template_string(f'''
        <h2>User Profile #{user_id}</h2>
        <p><strong>Username:</strong> {user[0]}</p>
        <p><strong>Email:</strong> {user[1]}</p>
        <p><strong>Balance:</strong> ${user[2]}</p>
        <a href="/profile/{user_id + 1}">Next User</a> | <a href="/">Home</a>
        ''')
    else:
        return "<h2>User not found</h2><a href='/'>Home</a>"

@app.route('/admin/users')
def admin_users():
    """Admin panel with weak access control"""
    # Weak access control - only checks if user_id is set
    if 'user_id' not in session:
        session['user_id'] = 1  # Auto-login as admin for testing
    
    conn = sqlite3.connect('test_db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    users_html = ''.join([
        f'<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td><td>{user[3]}</td><td>${user[4]}</td></tr>'
        for user in users
    ])
    
    return render_template_string(f'''
    <h2>Admin Panel - All Users</h2>
    <table border="1">
        <tr><th>ID</th><th>Username</th><th>Password</th><th>Email</th><th>Balance</th></tr>
        {users_html}
    </table>
    <a href="/">Back to Home</a>
    ''')

# CSRF Vulnerability
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """Money transfer without CSRF protection"""
    if request.method == 'POST':
        from_user = request.form.get('from_user', '1')
        to_user = request.form.get('to_user', '')
        amount = request.form.get('amount', '0')
        
        # Simulate transfer (no actual database update)
        return render_template_string(f'''
        <h2>Transfer Completed!</h2>
        <p>Transferred ${amount} from User {from_user} to User {to_user}</p>
        <p><strong>Note:</strong> This form has no CSRF protection!</p>
        <a href="/transfer">Make Another Transfer</a> | <a href="/">Home</a>
        ''')
    
    return render_template_string('''
    <h2>Money Transfer</h2>
    <form method="POST">
        <input type="hidden" name="from_user" value="1">
        To User ID: <input type="number" name="to_user" required><br><br>
        Amount: $<input type="number" name="amount" step="0.01" required><br><br>
        <input type="submit" value="Transfer Money">
    </form>
    <p><strong>Security Issue:</strong> No CSRF token protection!</p>
    <a href="/">Back to Home</a>
    ''')

# Command Injection Vulnerability
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    """Command injection in ping tool"""
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        try:
            # Vulnerable command execution
            command = f"ping -c 3 {host}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            
            return render_template_string(f'''
            <h2>Ping Results</h2>
            <p>Command executed: <code>{command}</code></p>
            <pre>{result.stdout}</pre>
            <pre style="color: red;">{result.stderr}</pre>
            <a href="/ping">Ping Again</a> | <a href="/">Home</a>
            ''')
        except Exception as e:
            return f"<h2>Error</h2><p>Command failed: {str(e)}</p><a href='/ping'>Try Again</a>"
    
    return render_template_string('''
    <h2>Network Ping Tool</h2>
    <form method="POST">
        <input type="text" name="host" placeholder="Enter host to ping..." required>
        <input type="submit" value="Ping">
    </form>
    <p>Hint: Try command injection like <code>127.0.0.1; whoami</code></p>
    <a href="/">Back to Home</a>
    ''')

# LFI Vulnerability
@app.route('/file')
def file_read():
    """Local File Inclusion vulnerability"""
    filename = request.args.get('name', '')
    
    if filename:
        try:
            # Vulnerable file reading - no path validation
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return render_template_string(f'''
            <h2>File Content</h2>
            <p>Reading file: <code>{filename}</code></p>
            <pre>{content[:2000]}...</pre>
            <a href="/file">Read Another File</a> | <a href="/">Home</a>
            ''')
        except Exception as e:
            return f"<h2>Error</h2><p>Could not read file: {str(e)}</p><a href='/file'>Try Again</a>"
    
    return render_template_string('''
    <h2>File Reader</h2>
    <form method="GET">
        <input type="text" name="name" placeholder="Enter filename..." required style="width: 400px;">
        <input type="submit" value="Read File">
    </form>
    <p>Hint: Try path traversal like <code>../../../etc/passwd</code></p>
    <a href="/">Back to Home</a>
    ''')

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("🔒 Starting Vulnerable Test Application...")
    print("Available at: http://localhost:5001")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("    Only use for security testing in isolated environments.")
    
    app.run(host='0.0.0.0', port=5001, debug=True)
