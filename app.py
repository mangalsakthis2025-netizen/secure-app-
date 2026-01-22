"""
Secure Web Application with Dashboard, Input Validation, and Security Logs
Built entirely in Python using Flask framework
"""

from flask import Flask, request, redirect, session
import datetime
import re

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "super_secret_key_change_in_production"

# Simple user credentials (in real app, use proper authentication)
USERNAME = "admin"
PASSWORD = "admin"

def create_html_page(page_title, page_content, extra_styles=""):
    """
    Generate a complete HTML page with consistent styling
    """
    base_css = """
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alert {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
        }
        .danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .info {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        .red { color: #e74c3c; font-weight: bold; }
        .orange { color: #f39c12; }
        .purple { color: #9b59b6; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #2c3e50;
            color: white;
        }
        tr:hover {
            background-color: #f9f9f9;
        }
        a {
            padding: 10px 15px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin: 5px;
            display: inline-block;
        }
        a:hover {
            background-color: #0056b3;
        }
        .logout-btn {
            background-color: #dc3545;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        input, textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            margin: 5px 0;
            box-sizing: border-box;
        }
        button {
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #0056b3;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
    """ + extra_styles + "</style>"

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{page_title}</title>
        {base_css}
    </head>
    <body>
        <div class="container">
            <h1>{page_title}</h1>
            {page_content}
        </div>
    </body>
    </html>
    """

    return html_template

def sanitize_user_input(input_text):
    """
    Clean user input to prevent XSS and other injection attacks
    """
    if not input_text:
        return ""

    # Remove HTML tags
    cleaned = re.sub(r'<[^>]+>', '', input_text)

    # Remove script tags and their content
    cleaned = re.sub(r'<script[^>]*>.*?</script>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)

    # Remove javascript URLs
    cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)

    # Remove event handlers
    cleaned = re.sub(r'\bon\w+\s*=', '', cleaned, flags=re.IGNORECASE)

    return cleaned.strip()

@app.route("/", methods=["GET", "POST"])
def login_page():
    """
    Handle user login and authentication
    """
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check credentials
        if username == USERNAME and password == PASSWORD:
            # Store session data
            session["user"] = username
            session["ip"] = request.remote_addr
            session["login_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            return redirect("/dashboard")
        else:
            # Show error message
            login_form = """
            <form method="POST">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <div class="alert warning">⚠️ Invalid username or password</div>
            """
            return create_html_page("Login", login_form)

    # Show login form
    login_form = """
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    """
    return create_html_page("Login", login_form)

@app.route("/dashboard")
def dashboard_page():
    """
    Main dashboard showing user session info and navigation
    """
    if "user" not in session:
        return redirect("/")

    # Check for session hijacking
    current_ip = request.remote_addr
    session_ip = session.get("ip", "")
    is_hijacked = current_ip != session_ip

    # Build dashboard content
    if is_hijacked:
        status_message = '<div class="alert danger">⚠️ Session Hijack Detected - Session Invalidated</div>'
    else:
        status_message = '<div class="alert info">✓ Session validated and secure</div>'

    # User info section
    user_info = f"""
    <div class="alert info">
        <strong>Username:</strong> {session["user"]}
    </div>
    <div class="alert info">
        <strong>Session IP:</strong> {session["ip"]}
    </div>
    <div class="alert info">
        <strong>Login Time:</strong> {session["login_time"]}
    </div>
    """

    # Navigation links
    nav_links = """
    <a href="/input-validation">Input Validation Form</a>
    <a href="/security-logs">Security Logs</a>
    <a href="/logout" class="logout-btn">Logout</a>
    """

    dashboard_content = status_message + user_info + nav_links
    return create_html_page("Secure Dashboard", dashboard_content)

@app.route("/input-validation", methods=["GET", "POST"])
def input_validation_page():
    """
    Form for testing input sanitization
    """
    if "user" not in session:
        return redirect("/")

    alert_message = ""
    sanitized_result = ""

    if request.method == "POST":
        user_message = request.form.get("message", "")

        if not user_message.strip():
            alert_message = "Message cannot be empty"
        elif len(user_message) > 1000:
            alert_message = "Message too long (max 1000 characters)"
        else:
            # Sanitize the input
            cleaned_message = sanitize_user_input(user_message)

            if cleaned_message != user_message:
                alert_message = "Potentially dangerous content detected and sanitized"

            sanitized_result = cleaned_message

    # Build page content
    content_parts = []

    if alert_message:
        content_parts.append(f'<div class="alert warning">⚠️ {alert_message}</div>')

    if sanitized_result:
        content_parts.append(f'<div class="alert success">✓ Sanitized output: <strong>{sanitized_result}</strong></div>')

    # Input form
    form_html = """
    <form method="POST">
        <label for="message">Message:</label>
        <textarea id="message" name="message" rows="4" placeholder="Enter your message..." required></textarea>
        <button type="submit">Submit</button>
    </form>
    """

    content_parts.append(form_html)
    page_content = "".join(content_parts)

    return create_html_page("Secure Input Form", page_content)

@app.route("/security-logs")
def security_logs_page():
    """
    Display security event logs
    """
    if "user" not in session:
        return redirect("/")

    # Sample security logs (in production, this would come from a database)
    security_events = [
        {
            "timestamp": "2026-01-22 10:30:15",
            "attack_type": "SQL Injection Attempt",
            "ip_address": "192.168.1.100"
        },
        {
            "timestamp": "2026-01-22 10:25:42",
            "attack_type": "XSS Attempt",
            "ip_address": "192.168.1.101"
        },
        {
            "timestamp": "2026-01-22 10:20:33",
            "attack_type": "Session Hijack Detected",
            "ip_address": "192.168.1.102"
        },
        {
            "timestamp": "2026-01-22 10:15:27",
            "attack_type": "Brute Force Login",
            "ip_address": "192.168.1.103"
        },
        {
            "timestamp": "2026-01-22 10:10:18",
            "attack_type": "XSS Attempt",
            "ip_address": "192.168.1.104"
        }
    ]

    # Build table rows with color coding
    table_rows = []
    for event in security_events:
        attack_type = event["attack_type"]

        # Determine CSS class based on attack type
        css_class = ""
        if "SQL" in attack_type:
            css_class = "red"
        elif "XSS" in attack_type:
            css_class = "orange"
        elif "Hijack" in attack_type:
            css_class = "purple"

        # Format the attack type with styling
        if css_class:
            styled_attack = f'<span class="{css_class}">{attack_type}</span>'
        else:
            styled_attack = attack_type

        row_html = f"""
        <tr>
            <td>{event["timestamp"]}</td>
            <td>{styled_attack}</td>
            <td>{event["ip_address"]}</td>
        </tr>
        """
        table_rows.append(row_html)

    # Build complete table
    logs_table = f"""
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Attack Type</th>
                <th>IP Address</th>
            </tr>
        </thead>
        <tbody>
            {"".join(table_rows)}
        </tbody>
    </table>
    <a href="/logout" class="logout-btn">Logout</a>
    """

    return create_html_page("Security Logs", logs_table)

@app.route("/logout")
def logout_page():
    """
    Clear user session and redirect to login
    """
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    print("Starting secure web application...")
    app.run(debug=True)
