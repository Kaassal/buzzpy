# Import libraries
import logging
from flask import Flask, render_template, request, redirect, url_for
from logging.handlers import RotatingFileHandler

# Logging setup
LOGGING_FORMAT = logging.Formatter("%(asctime)s %(message)s")  # Fixed typo in message
FUNNEL_LOGGER = logging.getLogger("FunnelLogger")
FUNNEL_LOGGER.setLevel(logging.INFO)
FUNNEL_HANDLER = RotatingFileHandler("http_audits.log", maxBytes=2000, backupCount=5)
FUNNEL_HANDLER.setFormatter(LOGGING_FORMAT)
FUNNEL_LOGGER.addHandler(FUNNEL_HANDLER)

# Honeypot
def web_honeypot(address, port=8080, input_username="admin", input_password="password"):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("wp-admin.html")

    @app.route("/wp-admin-login", methods=["POST"])
    def login():
        username = request.form['username']
        password = request.form['password']
        
        ip_address = request.remote_addr  
        
        FUNNEL_LOGGER.info(f'Client {ip_address} attempted login with username: {username} and password: {password}')

        if username == input_username and password == input_password:
            return 'Login successful!'
        else:
            return 'Login Failed try again'

    return app.run(debug=True, port=port, host=address)