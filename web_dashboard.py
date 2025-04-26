# Import library dependencies.
from dash import Dash, html, dash_table, dcc, Input, Output, no_update, State
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from dash_bootstrap_templates import load_figure_template
from pathlib import Path
from dotenv import load_dotenv
import os
import locale
import json
import time

# Import project python file dependencies.
from dashboard_data_parser import *

# Constants.
# Get base directory of where user is running buzzpy from.
base_dir = Path(__file__).parent
# Source log file paths with glob patterns to include rotated files
log_dir = base_dir / "log_files"

# Define full paths for log files including base directory
ssh_creds_log_file_path = str(log_dir / "audits.log")
ssh_cmds_log_file_path = str(log_dir / "cmd_audits.log")
http_url_log_file_path = str(log_dir / "http_url_audits.log")
http_creds_log_file_path = str(log_dir / "http_audits.log")

# Create log_files directory if it doesn't exist
log_dir.mkdir(exist_ok=True)

# Ensure log files exist (create empty ones if they don't)
for log_file in [
    ssh_creds_log_file_path,
    ssh_cmds_log_file_path,
    http_url_log_file_path,
    http_creds_log_file_path,
]:
    if not Path(log_file).exists():
        Path(log_file).touch()

# Load dotenv() to capture environment variable.
dotenv_path = Path("public.env")
load_dotenv(dotenv_path=dotenv_path)

# Load translations from JSON file
with open(Path(base_dir) / "config" / "locales.json", "r") as f:
    translations = json.load(f)

# Available locales
LOCALES = {"en_US": "English", "es_ES": "Español"}


def set_locale(selected_locale):
    try:
        locale.setlocale(locale.LC_ALL, selected_locale)
    except locale.Error:
        print(
            f"[WARNING] Failed to set locale {selected_locale}, falling back to default"
        )
        locale.setlocale(locale.LC_ALL, "")


# Translations
TRANSLATIONS = {
    "en_US": {
        "intelligence_data": "Intelligence Data",
        "ssh_credentials": "SSH Credentials",
        "ssh_commands": "SSH Commands",
        "http_login_attempts": "HTTP Login Attempts",
        "http_requests": "HTTP Requests",
        "refresh": "Refresh Dashboard",
        "country_distribution": "Country Distribution",
    },
    "es_ES": {
        "intelligence_data": "Datos de Inteligencia",
        "ssh_credentials": "Credenciales SSH",
        "ssh_commands": "Comandos SSH",
        "http_login_attempts": "Intentos de Inicio de Sesión HTTP",
        "http_requests": "Solicitudes HTTP",
        "refresh": "Actualizar Panel",
        "country_distribution": "Distribución por País",
    },
}


def get_translation(key, selected_locale="en_US"):
    return TRANSLATIONS.get(selected_locale, TRANSLATIONS["en_US"]).get(key, key)


# Pass log files to dataframe conversion with full paths
ssh_creds_log_df = parse_creds_audits_log(ssh_creds_log_file_path)
ssh_cmds_log_df = parse_cmd_audits_log(ssh_cmds_log_file_path)
http_url_log_df = parse_http_url_audits_log(http_url_log_file_path)
http_creds_log_df = parse_http_creds_audits_log(http_creds_log_file_path)

# Python Dash (& Dash Bootstrap) Constants.
# Load the Solar theme from Python Dash Bootstrap
load_figure_template(["solar"])
dbc_css = (
    "https://cdn.jsdelivr.net/gh/AnnMarieW/dash-bootstrap-templates@V1.0.4/dbc.min.css"
)

# Source the Buzzpy logo for dashboard
image = "buzzpylogo.png"

# Create assets directory and subdirectories if they don't exist
assets_dir = base_dir / "assets" / "images"
assets_dir.mkdir(parents=True, exist_ok=True)

# Default to a simple text title if image not found
logo_path = assets_dir / "buzzpylogo.png"
if logo_path.exists():
    image = f"assets/images/{image}"

# Set the value to True in (public.env) if you want country code lookup as default.
country = os.getenv("COUNTRY", "False")  # Default to False if not set
print(f"Country code lookup is: {country}")  # Debug print

# Declare Dash App, apply SOLAR theme.
app = Dash(__name__, external_stylesheets=[dbc.themes.SOLAR, dbc_css])
app.title = "Buzzpy"
app._favicon = "images/buzzpyfavicon.ico"  # Use relative path for favicon

# Service selection dropdown options
service_options = [
    {"label": translations["EN"]["services"]["all"], "value": "all"},
    {"label": translations["EN"]["services"]["ssh"], "value": "ssh"},
    {"label": translations["EN"]["services"]["http"], "value": "http"},
]

# Language selection dropdown options
language_options = [
    {"label": "EN", "value": "EN"},
    {"label": "ES", "value": "ES"},
]


def create_service_stats(selected_service, selected_lang="EN"):
    """Create service-specific statistics based on selected service"""
    graphs = []
    trans = translations[selected_lang]
    ssh_country_df = pd.DataFrame()  # Initialize empty DataFrame
    http_country_df = pd.DataFrame()  # Initialize empty DataFrame

    try:
        # Process country codes first if enabled
        if country == "True":
            try:
                if selected_service in ["all", "ssh"]:
                    print("[DEBUG] Processing SSH country codes")
                    ssh_country_df = ip_to_country_code(ssh_creds_log_df)

                if selected_service in ["all", "http"]:
                    print("[DEBUG] Processing HTTP country codes")
                    combined_http_df = pd.concat(
                        [
                            http_creds_log_df[["ip_address"]],
                            http_url_log_df[["ip_address"]],
                        ]
                    ).drop_duplicates()
                    http_country_df = ip_to_country_code(combined_http_df)
            except Exception as e:
                print(f"[ERROR] Failed to process country codes: {e}")

        if selected_service == "http" or selected_service == "all":
            # Calculate HTTP statistics
            http_ip_data = top_10_calculator(http_creds_log_df, "ip_address")
            http_url_data = top_10_calculator(http_url_log_df, "url", truncate=True)
            http_method_data = top_10_calculator(http_url_log_df, "method")

            if not http_url_data.empty:
                # Create URL graph with improved layout and hover info
                url_fig = go.Figure(
                    data=[
                        go.Bar(
                            x=http_url_data["url"],
                            y=http_url_data["frequency"],
                            text=None,
                            showlegend=False,
                            hovertemplate=f"<b>{trans['table']['url']}:</b> %{{x}}<br><b>{trans['graph']['frequency']}:</b> %{{y}}<extra></extra>",
                        )
                    ]
                )

                url_fig.update_layout(
                    template="solar",
                    title={
                        "text": f"{trans['graph']['top_10_urls']}<br><span style='font-size: 12px; color: gray'>{trans['graph']['hover_urls']}</span>",
                        "xanchor": "left",
                        "yanchor": "top",
                    },
                    xaxis={
                        "showticklabels": False,
                        "title": trans["table"]["url"],
                        "showgrid": False,
                    },
                    yaxis={
                        "title": trans["graph"]["frequency"],
                        "showgrid": True,
                        "gridcolor": "#073642",
                    },
                    height=450,
                    margin={"t": 100, "b": 50, "l": 50, "r": 20},
                    hoverlabel={"align": "left"},
                    plot_bgcolor="#002b36",
                    paper_bgcolor="#1e434a",
                    bargap=0.2,
                )

                if selected_service == "http":
                    graphs.extend(
                        [
                            dbc.Col(
                                dcc.Graph(
                                    figure=px.bar(
                                        http_ip_data,
                                        x="ip_address",
                                        y="frequency",
                                        title=trans["graph"]["top_10_ips_http"],
                                        labels={
                                            "ip_address": trans["table"]["ip_address"],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["ip_address"],
                                    )
                                ),
                                width=6,
                            ),
                            dbc.Col(
                                dcc.Graph(figure=url_fig),
                                width=6,
                            ),
                        ]
                    )

                    # Add HTTP method distribution graph
                    if not http_method_data.empty:
                        graphs.append(
                            dbc.Col(
                                dcc.Graph(
                                    figure=px.bar(
                                        http_method_data,
                                        x="method",
                                        y="frequency",
                                        title=trans["http_methods"],
                                        labels={
                                            "method": trans["table"]["method"],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["method"],
                                    )
                                ),
                                width=12,
                            )
                        )

        if selected_service == "all" or selected_service == "ssh":
            ssh_ip_data = top_10_calculator(ssh_creds_log_df, "ip_address")
            ssh_user_data = top_10_calculator(ssh_creds_log_df, "username")
            ssh_pass_data = top_10_calculator(ssh_creds_log_df, "password")
            ssh_cmd_data = top_10_calculator(ssh_cmds_log_df, "Command")

            # Ensure DataFrames are not empty before creating graphs
            if not ssh_ip_data.empty and "frequency" in ssh_ip_data.columns:
                if selected_service == "ssh":
                    graphs.extend(
                        [
                            dbc.Col(
                                dcc.Graph(
                                    figure=px.bar(
                                        ssh_ip_data,
                                        x="ip_address",
                                        y="frequency",
                                        title=trans["graph"]["top_10_ips_ssh"],
                                        labels={
                                            "ip_address": trans["table"]["ip_address"],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["ip_address"],
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
                                        title=trans["top_10_users"],
                                        labels={
                                            "username": trans["table"]["username"],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["username"],
                                    )
                                ),
                                width=6,
                            ),
                        ]
                    )

        if selected_service == "all" or selected_service == "http":
            http_ip_data = top_10_calculator(http_url_log_df, "ip_address")
            http_url_data = top_10_calculator(http_url_log_df, "url")
            http_method_data = top_10_calculator(http_url_log_df, "method")

            # Create URL graph with improved layout and hover info
            url_fig = go.Figure(
                data=[
                    go.Bar(
                        x=http_url_data["url"],
                        y=http_url_data["frequency"],
                        text=None,
                        showlegend=False,
                        hovertemplate=f"<b>{trans['table']['url']}:</b> %{{x}}<br><b>{trans['graph']['frequency']}:</b> %{{y}}<extra></extra>",
                    )
                ]
            )

            url_fig.update_layout(
                template="solar",
                title={
                    "text": f"{trans['graph']['top_10_urls']}<br><span style='font-size: 12px; color: gray'>{trans['graph']['hover_urls']}</span>",
                    "xanchor": "left",
                    "yanchor": "top",
                },
                xaxis={
                    "showticklabels": False,
                    "title": trans["table"]["url"],
                    "showgrid": False,
                },
                yaxis={
                    "title": trans["graph"]["frequency"],
                    "showgrid": True,
                    "gridcolor": "#073642",
                },
                height=450,
                margin={"t": 100, "b": 50, "l": 50, "r": 20},
                hoverlabel={"align": "left"},
                plot_bgcolor="#002b36",  # Solar theme plot background
                paper_bgcolor="#1e434a",  # Solar theme paper background (border)
                bargap=0.2,
            )

            if country == "True":
                try:
                    print("[DEBUG] Processing HTTP country codes")
                    # Combine both HTTP logs for country code lookup
                    combined_http_df = pd.concat(
                        [
                            http_creds_log_df[
                                ["ip_address"]
                            ],  # Put creds first as it has known good IPs
                            http_url_log_df[["ip_address"]],
                        ]
                    ).drop_duplicates()

                    http_country_df = ip_to_country_code(combined_http_df)
                    print(f"[DEBUG] HTTP country DataFrame: {http_country_df.shape}")
                    print("[DEBUG] HTTP country codes found:")
                    print(http_country_df)
                except Exception as e:
                    print(f"[ERROR] Failed to generate HTTP country codes: {e}")
                    http_country_df = pd.DataFrame(
                        {"Country_Code": ["Error"], "frequency": [0]}
                    )

            if selected_service == "all":
                graphs.extend(
                    [
                        dbc.Col(
                            dcc.Graph(
                                figure=px.bar(
                                    ssh_ip_data,
                                    x="ip_address",
                                    y="frequency",
                                    title=trans["graph"]["top_10_ips_ssh"],
                                    labels={
                                        "ip_address": trans["table"]["ip_address"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["ip_address"],
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
                                    title=trans["graph"]["top_10_ips_http"],
                                    labels={
                                        "ip_address": trans["table"]["ip_address"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["ip_address"],
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
                                    title=trans["top_10_users"],
                                    labels={
                                        "username": trans["table"]["username"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["username"],
                                )
                            ),
                            width=6,
                        ),
                        dbc.Col(
                            dcc.Graph(
                                figure=url_fig,
                            ),
                            width=6,
                        ),
                        dbc.Col(
                            dcc.Graph(
                                figure=px.bar(
                                    ssh_pass_data,
                                    x="password",
                                    y="frequency",
                                    title=trans["top_10_pass"],
                                    labels={
                                        "password": trans["table"]["password"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["password"],
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
                                    title=trans["http_methods"],
                                    labels={
                                        "method": trans["table"]["method"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["method"],
                                )
                            ),
                            width=6,
                        ),
                    ]
                )

                # Add country code graphs if enabled
                if (
                    country == "True"
                    and not http_country_df.empty
                    and not ssh_country_df.empty
                ):
                    graphs.extend(
                        [
                            dbc.Col(
                                dcc.Graph(
                                    figure=px.bar(
                                        ssh_country_df,
                                        x="Country_Code",
                                        y="frequency",
                                        title=trans["graph"]["country_dist_ssh"],
                                        labels={
                                            "Country_Code": trans["table"][
                                                "country_code"
                                            ],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["country_code"],
                                    )
                                ),
                                width=6,
                            ),
                            dbc.Col(
                                dcc.Graph(
                                    figure=px.bar(
                                        http_country_df,
                                        x="Country_Code",
                                        y="frequency",
                                        title=trans["graph"]["country_dist_http"],
                                        labels={
                                            "Country_Code": trans["table"][
                                                "country_code"
                                            ],
                                            "frequency": trans["graph"]["frequency"],
                                        },
                                    ).update_layout(
                                        yaxis_title=trans["graph"]["frequency"],
                                        xaxis_title=trans["table"]["country_code"],
                                    )
                                ),
                                width=6,
                            ),
                        ]
                    )

                graphs.append(
                    dbc.Col(
                        dcc.Graph(
                            figure=px.bar(
                                ssh_cmd_data,
                                x="Command",
                                y="frequency",
                                title=trans["top_10_cmds"],
                                labels={
                                    "Command": trans["table"]["command"],
                                    "frequency": trans["graph"]["frequency"],
                                },
                            ).update_layout(
                                yaxis_title=trans["graph"]["frequency"],
                                xaxis_title=trans["table"]["command"],
                            )
                        ),
                        width=12,
                    ),
                )
            else:  # http only
                graphs.extend(
                    [
                        dbc.Col(
                            dcc.Graph(
                                figure=px.bar(
                                    http_ip_data,
                                    x="ip_address",
                                    y="frequency",
                                    title=trans["graph"]["top_10_ips_http"],
                                    labels={
                                        "ip_address": trans["table"]["ip_address"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["ip_address"],
                                )
                            ),
                            width=4,
                        ),
                        dbc.Col(
                            dcc.Graph(figure=url_fig),
                            width=4,
                        ),
                        dbc.Col(
                            dcc.Graph(
                                figure=px.bar(
                                    http_method_data,
                                    x="method",
                                    y="frequency",
                                    title=trans["http_methods"],
                                    labels={
                                        "method": trans["table"]["method"],
                                        "frequency": trans["graph"]["frequency"],
                                    },
                                ).update_layout(
                                    yaxis_title=trans["graph"]["frequency"],
                                    xaxis_title=trans["table"]["method"],
                                )
                            ),
                            width=4,
                        ),
                    ]
                )

                # Add HTTP country code graph if enabled
                if (
                    country == "True"
                    and not http_country_df.empty
                    and "Country_Code" in http_country_df.columns
                ):
                    graphs.append(
                        dbc.Col(
                            dcc.Graph(
                                figure=px.bar(
                                    http_country_df,
                                    x="Country_Code",
                                    y="frequency",
                                    title="Country Distribution (HTTP)",
                                )
                            ),
                            width=12,
                        )
                    )

        return graphs
    except Exception as e:
        print(f"[ERROR] Error in create_service_stats: {e}")
        return []


def create_data_tables(selected_service="all", selected_lang="en"):
    """Create data tables based on selected service"""
    tables = []
    trans = translations[selected_lang]

    # Common table style settings
    table_style = {
        "style_table": {"overflowX": "auto"},
        "style_header": {
            "backgroundColor": "#002b36",
            "color": "#deb439",
            "font-weight": "bold",
        },
        "style_cell": {
            "backgroundColor": "#073642",
            "color": "#deb439",
            "textAlign": "left",
            "maxWidth": "400px",
            "whiteSpace": "normal",
            "wordBreak": "break-word",
        },
        "page_size": 10,
        "page_action": "native",
        "page_current": 0,
        "sort_action": "native",
        "sort_mode": "multi",
    }

    if selected_service in ["all", "ssh"]:
        # SSH Credentials Table
        if not ssh_creds_log_df.empty:
            sorted_creds_df = ssh_creds_log_df.sort_values(
                by="timestamp", ascending=False
            )
            tables.append(
                html.Div(
                    [
                        html.H4(trans["ssh_creds"], className="text-center"),
                        dash_table.DataTable(
                            id="ssh-creds-table",
                            columns=[
                                {"name": i, "id": i} for i in sorted_creds_df.columns
                            ],
                            data=sorted_creds_df.to_dict("records"),
                            sort_by=[{"column_id": "timestamp", "direction": "desc"}],
                            **table_style,
                        ),
                    ]
                )
            )

        # SSH Commands Table
        if not ssh_cmds_log_df.empty:
            sorted_cmds_df = ssh_cmds_log_df.sort_values(
                by="timestamp", ascending=False
            )
            tables.append(
                html.Div(
                    [
                        html.H4(trans["ssh_cmds"], className="text-center mt-4"),
                        dash_table.DataTable(
                            id="ssh-commands-table",
                            columns=[
                                {"name": i, "id": i} for i in sorted_cmds_df.columns
                            ],
                            data=sorted_cmds_df.to_dict("records"),
                            **table_style,
                        ),
                    ]
                )
            )

        # Add SSH Country Code Table if enabled
        if country == "True":
            try:
                ssh_country_df = ip_to_country_code(ssh_creds_log_df)
                if not ssh_country_df.empty:
                    tables.append(
                        html.Div(
                            [
                                html.H4(
                                    trans["country_dist"] + " (SSH)",
                                    className="text-center mt-4",
                                ),
                                dash_table.DataTable(
                                    id="ssh-country-code-table",
                                    columns=[
                                        {"name": i, "id": i}
                                        for i in ssh_country_df.columns
                                    ],
                                    data=ssh_country_df.to_dict("records"),
                                    **table_style,
                                ),
                            ]
                        )
                    )
            except Exception as e:
                print(f"Error creating SSH country table: {e}")

    if selected_service in ["all", "http"]:
        # HTTP Login Attempts Table
        if not http_creds_log_df.empty:
            sorted_creds_df = http_creds_log_df.sort_values(
                by="timestamp", ascending=False
            )
            tables.append(
                html.Div(
                    [
                        html.H4(trans["http_login"], className="text-center mt-4"),
                        dash_table.DataTable(
                            id="http-creds-table",
                            columns=[
                                {"name": i, "id": i} for i in sorted_creds_df.columns
                            ],
                            data=sorted_creds_df.to_dict("records"),
                            **table_style,
                        ),
                    ]
                )
            )

        # HTTP URLs Table
        if not http_url_log_df.empty:
            sorted_http_df = http_url_log_df.sort_values(
                by="timestamp", ascending=False
            )
            tables.append(
                html.Div(
                    [
                        html.H4(trans["http_reqs"], className="text-center mt-4"),
                        dash_table.DataTable(
                            id="http-urls-table",
                            columns=[
                                {"name": i, "id": i} for i in sorted_http_df.columns
                            ],
                            data=sorted_http_df.to_dict("records"),
                            **table_style,
                        ),
                    ]
                )
            )

        # Add HTTP Country Code Table if enabled
        if country == "True":
            try:
                # Combine both HTTP logs for country code lookup
                combined_http_df = pd.concat(
                    [http_url_log_df[["ip_address"]], http_creds_log_df[["ip_address"]]]
                ).drop_duplicates()

                http_country_df = ip_to_country_code(combined_http_df)
                if not http_country_df.empty:
                    tables.append(
                        html.Div(
                            [
                                html.H4(
                                    trans["country_dist"] + " (HTTP)",
                                    className="text-center mt-4",
                                ),
                                dash_table.DataTable(
                                    id="http-country-code-table",
                                    columns=[
                                        {"name": i, "id": i}
                                        for i in http_country_df.columns
                                    ],
                                    data=http_country_df.to_dict("records"),
                                    **table_style,
                                ),
                            ]
                        )
                    )
            except Exception as e:
                print(f"Error creating HTTP country table: {e}")

    return tables


def refresh_data():
    """Refresh data from all log files including rotated ones"""
    global ssh_creds_log_df, ssh_cmds_log_df, http_url_log_df, http_creds_log_df

    try:
        print("[DEBUG] Refreshing data...")
        ssh_creds_log_df = parse_creds_audits_log(ssh_creds_log_file_path)
        ssh_cmds_log_df = parse_cmd_audits_log(ssh_cmds_log_file_path)
        http_url_log_df = parse_http_url_audits_log(http_url_log_file_path)
        http_creds_log_df = parse_http_creds_audits_log(http_creds_log_file_path)
        print("[DEBUG] Data refresh complete")
    except Exception as e:
        print(f"[ERROR] Error refreshing data: {e}")


# Get default translations
default_trans = translations["EN"]


# Create skeleton components for loading states
def create_skeleton_graph():
    """Create a skeleton loader for graphs"""
    return html.Div(
        className="skeleton-graph",
        style={
            "height": "400px",
            "backgroundColor": "#073642",
            "borderRadius": "8px",
            "animation": "pulse 1.5s infinite",
            "marginBottom": "20px",
        },
    )


def create_skeleton_table():
    """Create a skeleton loader for tables"""
    rows = []
    for i in range(5):  # Show 5 skeleton rows
        rows.append(
            html.Div(
                className="skeleton-row",
                style={
                    "height": "40px",
                    "backgroundColor": "#073642",
                    "marginBottom": "8px",
                    "borderRadius": "4px",
                    "animation": "pulse 1.5s infinite",
                    "animationDelay": f"{i * 0.1}s",
                },
            )
        )
    return html.Div(
        children=rows,
        style={
            "padding": "16px",
            "backgroundColor": "#002b36",
            "borderRadius": "8px",
            "marginBottom": "20px",
        },
    )


# Add skeleton loading styles to the app layout
app.index_string = """
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            @keyframes pulse {
                0% { opacity: 0.6; }
                50% { opacity: 1; }
                100% { opacity: 0.6; }
            }
            .skeleton-graph, .skeleton-row {
                position: relative;
                overflow: hidden;
            }
            .skeleton-graph::after, .skeleton-row::after {
                content: "";
                position: absolute;
                top: 0;
                right: 0;
                bottom: 0;
                left: 0;
                transform: translateX(-100%);
                background: linear-gradient(
                    90deg,
                    rgba(255, 255, 255, 0) 0%,
                    rgba(255, 255, 255, 0.05) 50%,
                    rgba(255, 255, 255, 0) 100%
                );
                animation: shimmer 2s infinite;
            }
            @keyframes shimmer {
                100% { transform: translateX(100%); }
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
"""

# Define web application layout.
app.layout = dbc.Container(
    [
        dcc.Interval(
            id="interval-component",
            interval=30 * 1000,  # Changed to 30 seconds from 10 seconds
            n_intervals=0,
        ),
        # Honeypot Title and Logo
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        html.Img(
                            src=image,
                            style={"height": "35%", "width": "35%", "padding": "1.25%"},
                        )
                    ],
                    style={"textAlign": "center"},
                    className="dbc mb-4",
                ),
                width=12,
            ),
            justify="center",
        ),
        # Controls Row with dropdowns and button
        dbc.Row(
            dbc.Col(
                html.Div(
                    [
                        dcc.Dropdown(
                            id="language-selector",
                            options=language_options,
                            value="EN",
                            style={
                                "backgroundColor": "#b58900",
                                "color": "grey",
                                "borderRadius": "8px",
                                "width": "80px",
                                "display": "inline-block",
                                "marginRight": "10px",
                            },
                        ),
                        dcc.Dropdown(
                            id="service-selector",
                            options=service_options,
                            value="all",
                            style={
                                "backgroundColor": "#b58900",
                                "color": "grey",
                                "borderRadius": "8px",
                                "width": "400px",
                                "display": "inline-block",
                                "marginRight": "10px",
                            },
                        ),
                        dbc.Button(
                            default_trans["refresh_button"],
                            id="refresh-button",
                            color="primary",
                            style={"display": "inline-block"},
                        ),
                    ],
                    style={
                        "display": "flex",
                        "justifyContent": "center",
                        "alignItems": "center",
                        "gap": "10px",
                    },
                ),
                width=12,
            ),
            className="mb-4",
        ),
        # Loading container for graphs with skeleton state
        dbc.Row(
            id="skeleton-graphs",
            children=[
                dbc.Col(create_skeleton_graph(), width=6),
                dbc.Col(create_skeleton_graph(), width=6),
                dbc.Col(create_skeleton_graph(), width=6),
                dbc.Col(create_skeleton_graph(), width=6),
            ],
        ),
        # Dynamic Graphs Section
        dbc.Row(id="graphs-container", align="center", class_name="mb-4"),
        # Intelligence Data Section
        html.Div(
            [
                html.H3(
                    id="intelligence-title",
                    style={
                        "textAlign": "center",
                        "font-family": "Consolas, sans-serif",
                        "font-weight": "bold",
                    },
                ),
            ]
        ),
        # Loading container for tables with skeleton state
        html.Div(
            id="skeleton-tables",
            children=[
                create_skeleton_table(),
                create_skeleton_table(),
            ],
        ),
        # Data Tables Section
        html.Div(id="tables-container", className="dbc"),
    ]
)


@app.callback(
    [
        Output("graphs-container", "children"),
        Output("tables-container", "children"),
        Output("intelligence-title", "children"),
        Output("refresh-button", "children"),
        Output("service-selector", "options"),
        Output("skeleton-graphs", "style"),
        Output("skeleton-tables", "style"),
    ],
    [Input("refresh-button", "n_clicks"), Input("language-selector", "value")],
    [State("service-selector", "value")],
)
def update_dashboard(n_clicks, selected_lang, selected_service):
    """Update dashboard with manual refresh and localization"""
    try:
        print("[DEBUG] Refreshing data...")
        refresh_data()  # Refresh data from all log files
        # Add artificial delay to show loading state
        time.sleep(0.5)

        trans = translations[selected_lang]
        service_opts = [
            {"label": trans["services"][opt["value"]], "value": opt["value"]}
            for opt in service_options
        ]

        graphs = create_service_stats(selected_service, selected_lang)
        tables = create_data_tables(selected_service, selected_lang)

        print("[DEBUG] Dashboard update completed successfully")
        return (
            graphs,
            tables,
            trans["title"],
            trans["refresh_button"],
            service_opts,
            {"display": "none"},  # Hide skeleton graphs
            {"display": "none"},  # Hide skeleton tables
        )
    except Exception as e:
        print(f"[ERROR] Dashboard update failed: {e}")
        import traceback

        print(traceback.format_exc())
        return (
            [],
            [],
            translations["EN"]["title"],
            translations["EN"]["refresh_button"],
            service_options,
            {"display": "none"},
            {"display": "none"},
        )


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", use_reloader=False)
