# Import library dependencies.
from dash import Dash, html, dash_table, dcc
from dash.dependencies import Input, Output
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
http_url_log_file_path = log_dir / "http_url_audits.log"

# Create log_files directory if it doesn't exist
log_dir.mkdir(exist_ok=True)

# Ensure log files exist (create empty ones if they don't)
if not ssh_creds_log_file_path.exists():
    ssh_creds_log_file_path.touch()
if not ssh_cmds_log_file_path.exists():
    ssh_cmds_log_file_path.touch()
if not http_url_log_file_path.exists():
    http_url_log_file_path.touch()

# Load dotenv() to capture environment variable.
dotenv_path = Path("public.env")
load_dotenv(dotenv_path=dotenv_path)

# Pass log files to dataframe conversion.
ssh_creds_log_df = parse_creds_audits_log(str(ssh_creds_log_file_path))
ssh_cmds_log_df = parse_cmd_audits_log(str(ssh_cmds_log_file_path))
http_url_log_df = parse_http_url_audits_log(str(http_url_log_file_path))

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

# Set the value to True in (public.env) if you want country code lookup as default.
country = os.getenv("COUNTRY", "False")  # Default to False if not set
print(f"Country code lookup is: {country}")  # Debug print

# Declare Dash App, apply SOLAR theme.
app = Dash(__name__, external_stylesheets=[dbc.themes.SOLAR, dbc_css])
app.title = "Buzzpy"

# Service selection dropdown options
service_options = [
    {"label": "All Services", "value": "all"},
    {"label": "SSH", "value": "ssh"},
    {"label": "HTTP", "value": "http"},
]


def create_service_stats(selected_service):
    """Create service-specific statistics based on selected service"""
    if selected_service == "all" or selected_service == "ssh":
        ssh_ip_data = top_10_calculator(ssh_creds_log_df, "ip_address")
        ssh_user_data = top_10_calculator(ssh_creds_log_df, "username")
        ssh_pass_data = top_10_calculator(ssh_creds_log_df, "password")
        ssh_cmd_data = top_10_calculator(ssh_cmds_log_df, "Command")
        if country == "True":
            ssh_country_df = ip_to_country_code(ssh_creds_log_df)
            ssh_country_data = top_10_calculator(ssh_country_df, "Country_Code")

    if selected_service == "all" or selected_service == "http":
        http_ip_data = top_10_calculator(http_url_log_df, "ip_address")
        http_url_data = top_10_calculator(http_url_log_df, "url")
        http_method_data = top_10_calculator(http_url_log_df, "method")
        if country == "True":
            http_country_df = ip_to_country_code(http_url_log_df)
            http_country_data = top_10_calculator(http_country_df, "Country_Code")

    graphs = []

    if selected_service == "all":
        # Combine data from both services
        graphs = [
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_ip_data,
                        x="ip_address",
                        y="frequency",
                        title="Top 10 IP Addresses (SSH)",
                    )
                ),
                width=6,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_ip_data,
                        x="ip_address",
                        y="frequency",
                        title="Top 10 IP Addresses (HTTP)",
                    )
                ),
                width=6,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_user_data,
                        x="username",
                        y="frequency",
                        title="Top 10 Usernames (SSH)",
                    )
                ),
                width=6,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_url_data,
                        x="url",
                        y="frequency",
                        title="Top 10 URLs (HTTP)",
                    )
                ),
                width=6,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_pass_data,
                        x="password",
                        y="frequency",
                        title="Top 10 Passwords (SSH)",
                    )
                ),
                width=6,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_method_data,
                        x="method",
                        y="frequency",
                        title="HTTP Methods Distribution",
                    )
                ),
                width=6,
            ),
        ]
        
        # Add country code graphs if enabled
        if country == "True":
            graphs.extend([
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            ssh_country_data,
                            x="Country_Code",
                            y="frequency",
                            title="Country Distribution (SSH)",
                        )
                    ),
                    width=6,
                ),
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            http_country_data,
                            x="Country_Code",
                            y="frequency",
                            title="Country Distribution (HTTP)",
                        )
                    ),
                    width=6,
                ),
            ])
            
        graphs.append(
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_cmd_data,
                        x="Command",
                        y="frequency",
                        title="Top 10 SSH Commands",
                    )
                ),
                width=12,
            ),
        )
    elif selected_service == "ssh":
        graphs = [
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_ip_data,
                        x="ip_address",
                        y="frequency",
                        title="Top 10 IP Addresses",
                    )
                ),
                width=4,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_user_data,
                        x="username",
                        y="frequency",
                        title="Top 10 Usernames",
                    )
                ),
                width=4,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_pass_data,
                        x="password",
                        y="frequency",
                        title="Top 10 Passwords",
                    )
                ),
                width=4,
            ),
        ]
        
        # Add country code graph if enabled
        if country == "True":
            graphs.append(
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            ssh_country_data,
                            x="Country_Code",
                            y="frequency",
                            title="Country Distribution",
                        )
                    ),
                    width=12,
                ),
            )
            
        graphs.append(
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        ssh_cmd_data,
                        x="Command",
                        y="frequency",
                        title="Top 10 Commands",
                    )
                ),
                width=12,
            ),
        )
    else:  # http
        graphs = [
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_ip_data,
                        x="ip_address",
                        y="frequency",
                        title="Top 10 IP Addresses",
                    )
                ),
                width=4,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_url_data, x="url", y="frequency", title="Top 10 URLs"
                    )
                ),
                width=4,
            ),
            dbc.Col(
                dcc.Graph(
                    figure=px.bar(
                        http_method_data,
                        x="method",
                        y="frequency",
                        title="HTTP Methods Distribution",
                    )
                ),
                width=4,
            ),
        ]
        
        # Add country code graph if enabled
        if country == "True":
            graphs.append(
                dbc.Col(
                    dcc.Graph(
                        figure=px.bar(
                            http_country_data,
                            x="Country_Code",
                            y="frequency",
                            title="Country Distribution",
                        )
                    ),
                    width=12,
                ),
            )

    return graphs


def create_data_tables(selected_service="all"):
    """Create data tables based on selected service"""
    tables = []

    if selected_service in ["all", "ssh"]:
        # SSH Credentials Table
        if not ssh_creds_log_df.empty:
            tables.append(
                html.Div([
                    html.H4("SSH Credentials Attempts", className="text-center"),
                    dash_table.DataTable(
                        id="ssh-creds-table",
                        columns=[{"name": i, "id": i} for i in ssh_creds_log_df.columns],
                        data=ssh_creds_log_df.to_dict("records"),
                        style_table={"overflowX": "auto"},
                        style_header={
                            "backgroundColor": "#002b36",
                            "color": "#deb439",
                            "font-weight": "bold"
                        },
                        style_cell={
                            "backgroundColor": "#073642",
                            "color": "#deb439",
                            "textAlign": "left",
                        },
                    ),
                ])
            )

            # Add Country Code Table for SSH if enabled
            if country == "True":
                try:
                    ssh_country_df = ip_to_country_code(ssh_creds_log_df)
                    if not ssh_country_df.empty:
                        tables.append(
                            html.Div([
                                html.H4("Country Code Distribution (SSH)", className="text-center mt-4"),
                                dash_table.DataTable(
                                    id="ssh-country-code-table",
                                    columns=[{"name": i, "id": i} for i in ssh_country_df.columns],
                                    data=ssh_country_df.to_dict("records"),
                                    style_table={"overflowX": "auto"},
                                    style_header={
                                        "backgroundColor": "#002b36",
                                        "color": "#deb439",
                                        "font-weight": "bold"
                                    },
                                    style_cell={
                                        "backgroundColor": "#073642",
                                        "color": "#deb439",
                                        "textAlign": "left",
                                    },
                                ),
                            ])
                        )
                except Exception as e:
                    print(f"Error creating SSH country table: {e}")

        # SSH Commands Table
        if not ssh_cmds_log_df.empty:
            tables.append(
                html.Div([
                    html.H4("SSH Commands", className="text-center mt-4"),
                    dash_table.DataTable(
                        id="ssh-commands-table",
                        columns=[{"name": i, "id": i} for i in ssh_cmds_log_df.columns],
                        data=ssh_cmds_log_df.to_dict("records"),
                        style_table={"overflowX": "auto"},
                        style_header={
                            "backgroundColor": "#002b36",
                            "color": "#deb439",
                            "font-weight": "bold"
                        },
                        style_cell={
                            "backgroundColor": "#073642",
                            "color": "#deb439",
                            "textAlign": "left",
                        },
                    ),
                ])
            )

    if selected_service in ["all", "http"]:
        # HTTP URLs Table
        if not http_url_log_df.empty:
            tables.append(
                html.Div([
                    html.H4("HTTP Requests", className="text-center mt-4"),
                    dash_table.DataTable(
                        id="http-urls-table",
                        columns=[{"name": i, "id": i} for i in http_url_log_df.columns],
                        data=http_url_log_df.to_dict("records"),
                        style_table={"overflowX": "auto"},
                        style_header={
                            "backgroundColor": "#002b36",
                            "color": "#deb439",
                            "font-weight": "bold"
                        },
                        style_cell={
                            "backgroundColor": "#073642",
                            "color": "#deb439",
                            "textAlign": "left",
                        },
                    ),
                ])
            )

            # Add Country Code Table for HTTP if enabled
            if country == "True":
                try:
                    http_country_df = ip_to_country_code(http_url_log_df)
                    if not http_country_df.empty:
                        tables.append(
                            html.Div([
                                html.H4("Country Code Distribution (HTTP)", className="text-center mt-4"),
                                dash_table.DataTable(
                                    id="http-country-code-table",
                                    columns=[{"name": i, "id": i} for i in http_country_df.columns],
                                    data=http_country_df.to_dict("records"),
                                    style_table={"overflowX": "auto"},
                                    style_header={
                                        "backgroundColor": "#002b36",
                                        "color": "#deb439",
                                        "font-weight": "bold"
                                    },
                                    style_cell={
                                        "backgroundColor": "#073642",
                                        "color": "#deb439",
                                        "textAlign": "left",
                                    },
                                ),
                            ])
                        )
                except Exception as e:
                    print(f"Error creating HTTP country table: {e}")

    return tables


# Define web application layout.
app.layout = dbc.Container(
    [
        # Honeypot Title and Service Selection
        dbc.Row(
            [
                dbc.Col(
                    html.Div(
                        [html.Img(src=image, style={"height": "25%", "width": "25%"})],
                        style={"textAlign": "center"},
                        className="dbc",
                    ),
                    width=8,
                ),
                dbc.Col(
                    dcc.Dropdown(
                        id="service-selector",
                        options=service_options,
                        value="all",
                        style={"backgroundColor": "#deb439", "color": "#839496"},
                    ),
                    width=4,
                ),
            ],
            align="center",
            class_name="mb-4",
        ),
        # Dynamic Graphs Section
        dbc.Row(id="graphs-container", align="center", class_name="mb-4"),
        # Intelligence Data Section
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
        # Data Tables Section
        html.Div(id="tables-container", className="dbc"),
    ]
)


@app.callback(
    Output("graphs-container", "children"), [Input("service-selector", "value")]
)
def update_graphs(selected_service):
    return create_service_stats(selected_service)


@app.callback(
    Output("tables-container", "children"), [Input("service-selector", "value")]
)
def update_tables(selected_service):
    return create_data_tables(selected_service)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")
