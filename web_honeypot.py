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
LOGGING_FORMAT = logging.Formatter("%(asctime)s %(message)s")

# Configure loggers
def configure_logger(name, filename):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        f"log_files/{filename}", maxBytes=2000, backupCount=5
    )
    handler.setFormatter(LOGGING_FORMAT)
    logger.addHandler(handler)
    return logger

# Initialize loggers
FUNNEL_LOGGER = configure_logger("HttpLogger", "http_audits.log")
URL_LOGGER = configure_logger("HttpUrlLogger", "http_url_audits.log")

def web_honeypot(
    address, 
    port=8080, 
    input_username="admin", 
    input_password="password", 
    demo_mode=False
):
    # Initialize Flask with custom static configuration
    app = Flask(
        __name__,
        static_folder='assets',        # Points to the assets directory
        static_url_path='/assets',     # URL path for static files
        template_folder='templates'    # Explicit template folder
    )
    
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
            return render_template("wp-dashboard.html")
        return render_template("wp-admin.html", error=strings["error_message"])

    # WordPress-like routes
    @app.route("/wp-admin")
    def wp_admin():
        return redirect("/")

    @app.route("/wp-login.php")
    def wp_login():
        return redirect("/")

    @app.route("/xmlrpc.php", methods=["GET", "POST"])
    def xmlrpc():
        return "XML-RPC server accepts POST requests only.", 405

    print(f"Web honeypot running on {address}:{port} ({'DEMO' if demo_mode else 'PROD'} MODE)")
    return app.run(debug=False, port=port, host=address, use_reloader=False)