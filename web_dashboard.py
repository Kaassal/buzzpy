# Import library dependencies.
from dash import Dash, html, dash_table, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
from dash_bootstrap_templates import load_figure_template
from pathlib import Path
from dotenv import load_dotenv
import os

# Import project python file dependencies.
from dashboard_data_parser import *
from buzzpy import *

# Constants.
# Get base directory of where user is running buzzpy from.
base_dir = Path(__file__).parent
# Source log file paths
log_dir = base_dir / "log_files"
ssh_creds_log_file_path = log_dir / "audits.log"
ssh_cmds_log_file_path = log_dir / "cmd_audits.log"

# Create log_files directory if it doesn't exist
log_dir.mkdir(exist_ok=True)

# Ensure log files exist (create empty ones if they don't)
if not ssh_creds_log_file_path.exists():
    ssh_creds_log_file_path.touch()
if not ssh_cmds_log_file_path.exists():
    ssh_cmds_log_file_path.touch()

# Load dotenv() to capture environment variable.
dotenv_path = Path("public.env")
load_dotenv(dotenv_path=dotenv_path)

# Pass log files to dataframe conversion.
ssh_creds_log_df = parse_creds_audits_log(str(ssh_creds_log_file_path))
ssh_cmds_log_df = parse_cmd_audits_log(str(ssh_cmds_log_file_path))

# Pass dataframes to top_10 calculator to get the top 10 values in the dataframe.
top_ip_address = top_10_calculator(ssh_creds_log_df, "ip_address")
top_usernames = top_10_calculator(ssh_creds_log_df, "username")
top_passwords = top_10_calculator(ssh_creds_log_df, "password")
top_cmds = top_10_calculator(ssh_cmds_log_df, "Command")

# Pass IP address to calculate country code, then to the top_10 calculator.
# get_ip_to_country = ip_to_country_code(ssh_creds_log_df)
# top_country = top_10_calculator(get_ip_to_country, "Country_Code")

# Python Dash (& Dash Bootstrap) Constants.
# Load the Solar theme from Python Dash Bootstrap
load_figure_template(["solar"])
dbc_css = (
    "https://cdn.jsdelivr.net/gh/AnnMarieW/dash-bootstrap-templates@V1.0.4/dbc.min.css"
)

# Create assets directory and subdirectories if they don't exist
assets_dir = base_dir / "assets" / "images"
assets_dir.mkdir(parents=True, exist_ok=True)

# Default to a simple text title if image not found
image = None
logo_path = assets_dir / "buzzpy-logo-white.png"
if logo_path.exists():
    image = str(logo_path)


# Declare Dash App, apply SOLAR theme.
app = Dash(__name__, external_stylesheets=[dbc.themes.SOLAR, dbc_css])
# Provide web page title and Favicon.
app.title = "Buzzpy"

# Set the value to True in (public.env) if you want country code lookup as default. This does have impact on performance by default.
# If the script is erroring out with a Rate Limiting Error (HTTP CODE 429), set country to False in (public.env), this will not look up country codes and will not show dashboard.
country = os.getenv("COUNTRY")


# Fucntion to get country code lookup if country = True. This does have impact on performance. Default is set to False.
def country_lookup(country):
    if country == "True":
        get_ip_to_country = ip_to_country_code(ssh_creds_log_df)
        top_country = top_10_calculator(get_ip_to_country, "Country_Code")
        message = dbc.Col(
            dcc.Graph(figure=px.bar(top_country, x="Country_Code", y="frequency")),
            style={"width": "33%", "display": "inline-block"},
        )
    else:
        message = "No Country Panel Defined"
    return message


# Generate tables using DBC (Dash Bootstrap Component) library.
tables = html.Div(
    [
        dbc.Row(
            [
                dbc.Col(
                    dash_table.DataTable(
                        data=ssh_creds_log_df.to_dict("records"),
                        columns=[{"name": "IP Address", "id": "ip_address"}],
                        style_table={"width": "100%", "color": "black"},
                        style_cell={"textAlign": "left", "color": "#deb439"},
                        style_header={"fontWeight": "bold"},
                        page_size=10,
                    ),
                ),
                dbc.Col(
                    dash_table.DataTable(
                        data=ssh_creds_log_df.to_dict("records"),
                        columns=[{"name": "Usernames", "id": "username"}],
                        style_table={"width": "100%"},
                        style_cell={"textAlign": "left", "color": "#deb439"},
                        style_header={"fontWeight": "bold"},
                        page_size=10,
                    ),
                ),
                dbc.Col(
                    dash_table.DataTable(
                        data=ssh_creds_log_df.to_dict("records"),
                        columns=[{"name": "Passwords", "id": "password"}],
                        style_table={"width": "100%", "justifyContent": "center"},
                        style_cell={"textAlign": "left", "color": "#deb439"},
                        style_header={"fontWeight": "bold"},
                        page_size=10,
                    ),
                ),
            ]
        )
    ]
)
# Apply dark theme to the tables. Had to cast this to an HTML.Div with className to get the dark theme.
apply_table_theme = html.Div([tables], className="dbc")
# Define web application layout.
app.layout = dbc.Container(
    [
        # Honeypot Title.
        html.Div(
            [html.Img(src=image, style={"height": "25%", "width": "25%"})],
            style={"textAlign": "center"},
            className="dbc",
        ),
        # Row 1 - 3 Top 10 Dashboards, IP Address, Usernames, and Passwords.
        dbc.Row(
            [
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            top_ip_address, y="frequency", title="Top 10 IP Addresses"
                        )
                    ),
                    width=4,
                ),
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            top_usernames, y="frequency", title="Top 10 Usernames"
                        )
                    ),
                    width=4,
                ),
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            top_passwords, y="frequency", title="Top 10 Passwords"
                        )
                    ),
                    width=4,
                ),
            ],
            align="center",
            class_name="mb-4",
        ),
        # Row 2: Top 10 Commands + Country Codes.
        dbc.Row(
            [
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(top_cmds, y="frequency", title="Top 10 Commands")
                    ),
                    style={"width": "33%", "display": "inline-block"},
                ),
                country_lookup(country),
            ],
            align="center",
            class_name="mb-4",
        ),
        # Table Titles.
        html.Div(
            [
                html.H3(
                    "Intelligence Data",
                    style={
                        "textAlign": "center",
                        "font-family": "Consolas, sans-serif",
                        "font-weight": "bold",
                    },
                ),
            ]
        ),
        # Row 3: Tables. Usernames, Passwords, and IP Addresses.
        apply_table_theme,
    ]
)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
