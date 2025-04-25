# Import libraries
import logging
from flask import Flask, render_template, request, redirect, url_for
from logging.handlers import RotatingFileHandler

# String configurations for different modes
DEMO_STRINGS = {
    "server_header": "Apache/2.4.41 (Ubuntu) DEMO",
    "wp_version": "WordPress 6.0-DEMO",
    "success_message": "Demo login successful!",
    "error_message": "Invalid username or password (Demo Mode)"
}

REAL_STRINGS = {
    "server_header": "nginx/1.18.0 (Ubuntu)",
    "wp_version": "WordPress 6.4.3",
    "success_message": "Welcome back! Redirecting to dashboard...",
    "error_message": "Error: The password you entered for the username is incorrect."
}

def get_strings(demo_mode=False):
    return DEMO_STRINGS if demo_mode else REAL_STRINGS

# Logging setup
LOGGING_FORMAT = logging.Formatter("%(asctime)s %(message)s")  # Fixed typo in message

# Logger for login attempts
FUNNEL_LOGGER = logging.getLogger("HttpLogger")
FUNNEL_LOGGER.setLevel(logging.INFO)
FUNNEL_HANDLER = RotatingFileHandler(
    "log_files/http_audits.log", maxBytes=2000, backupCount=5
)
FUNNEL_HANDLER.setFormatter(LOGGING_FORMAT)
FUNNEL_LOGGER.addHandler(FUNNEL_HANDLER)

# Logger for URL paths
URL_LOGGER = logging.getLogger("HttpUrlLogger")
URL_LOGGER.setLevel(logging.INFO)
URL_HANDLER = RotatingFileHandler(
    "log_files/http_url_audits.log", maxBytes=2000, backupCount=5
)
URL_HANDLER.setFormatter(LOGGING_FORMAT)
URL_LOGGER.addHandler(URL_HANDLER)


# Honeypot
def web_honeypot(address, port=8080, input_username="admin", input_password="password", demo_mode=False):
    app = Flask(__name__)
    strings = get_strings(demo_mode)

    @app.after_request
    def add_headers(response):
        """Add server headers to simulate real/demo server"""
        response.headers['Server'] = strings["server_header"]
        response.headers['X-Powered-By'] = strings["wp_version"]
        return response

    @app.before_request
    def log_request():
        """Log all incoming request URLs and query parameters"""
        ip_address = request.remote_addr
        method = request.method
        url = request.url
        args = dict(request.args)

        # Log the full URL including query parameters
        URL_LOGGER.info(
            f"Client {ip_address} | Method: {method} | URL: {url} | Args: {args}"
        )

    @app.route("/")
    def index():
        return render_template("wp-admin.html", error=None)

    @app.route("/wp-admin-login", methods=["POST"])
    def login():
        username = request.form["username"]
        password = request.form["password"]
        ip_address = request.remote_addr

        FUNNEL_LOGGER.info(
            f"Client {ip_address} attempted login with username: {username} and password: {password}"
        )

        if username == input_username and password == input_password:
            return strings["success_message"]
        else:
            return render_template("wp-admin.html", error=strings["error_message"])

    # Add routes that look like real WordPress paths to attract attackers
    @app.route("/wp-admin")
    def wp_admin():
        return redirect("/")

    @app.route("/wp-login.php")
    def wp_login():
        return redirect("/")

    @app.route("/xmlrpc.php", methods=["GET", "POST"])
    def xmlrpc():
        return "XML-RPC server accepts POST requests only.", 405

    mode = "DEMO MODE" if demo_mode else "PRODUCTION MODE" 
    print(f"Web honeypot listening on {address}:{port} ({mode})")
    return app.run(debug=True, port=port, host=address)
