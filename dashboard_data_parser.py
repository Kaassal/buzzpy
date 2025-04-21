# Import library dependencies.
import pandas as pd
import re
import requests
import glob
from pathlib import Path
from functools import lru_cache

# This file parses the various log files. The log files have different "formats" or information provided, so needed to create unique parsers for each.
# Each of these parsers takes the log file, gathers the specific information provided in the log, then returns the data in columns/rows Pandas dataframe type.

# Update the log file name to match the new name in ssh_honeypot.py
creds_audits_log_file = "log_files/audits.log"  # Updated to match the new name
cmd_audits_log_file = "log_files/ssh_cmd_audits.log"  # Ensure consistency
http_url_audits_log_file = "log_files/http_url_audits.log"  # New HTTP URL log file


# Update the parsers to read all rotated log files.
def parse_creds_audits_log(creds_audits_log_file):
    """Parse SSH credentials log file, including rotated files."""
    try:
        data = []
        # Get base directory of the log file
        base_dir = str(Path(creds_audits_log_file).parent)
        # Use glob with correct pattern to find all rotated files
        log_files = glob.glob(f"{base_dir}/audits.log*")
        
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    # Parse log format: "timestamp Client IP connection attempt username: user, password: pass"
                    match = re.match(
                        r"(?:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) )?Client (.*?) connection attempt username: (.*?), password: (.*?)$",
                        line.strip(),
                    )
                    if match:
                        timestamp, ip_address, username, password = match.groups()
                        # Use current timestamp if not present in log
                        if not timestamp:
                            timestamp = "No timestamp"
                        data.append({
                            "timestamp": timestamp,
                            "ip_address": ip_address,
                            "username": username,
                            "password": password
                        })

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing credentials log: {e}")
        return pd.DataFrame(columns=["timestamp", "ip_address", "username", "password"])


def clean_command_text(command):
    """Clean command text by removing b prefix and apostrophes"""
    if isinstance(command, str):
        # Remove b prefix and clean apostrophes
        pattern = re.compile(r"^b'(.*)'$|^b\"(.*)\"$|^'(.*)'$|^\"(.*)\"$")
        match = pattern.match(command)
        if match:
            # Return the first non-None group
            return next(group for group in match.groups() if group is not None)
    return command

def parse_cmd_audits_log(cmd_audits_log_file):
    """Parse SSH command log file, including rotated files."""
    try:
        data = []
        base_dir = str(Path(cmd_audits_log_file).parent)
        log_files = glob.glob(f"{base_dir}/cmd_audits.log*")
        
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    # Parse log format: "timestamp Command: command Client: IP"
                    match = re.match(r"(?:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) )?Command: (.*?) Client: (.*?)$", line.strip())
                    if match:
                        timestamp, command, ip = match.groups()
                        if not timestamp:
                            timestamp = "No timestamp"
                        # Clean the command text before adding to data
                        cleaned_command = clean_command_text(command)
                        data.append({
                            "timestamp": timestamp,
                            "Command": cleaned_command,
                            "Client": ip
                        })

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing commands log: {e}")
        return pd.DataFrame(columns=["timestamp", "Command", "Client"])


def parse_http_url_audits_log(http_url_audits_log_file):
    """Parse HTTP URL log file, including rotated files."""
    try:
        data = []
        base_dir = str(Path(http_url_audits_log_file).parent)
        log_files = glob.glob(f"{base_dir}/http_url_audits.log*")
        
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    match = re.match(
                        r"(.*?) Client (.*?) \| Method: (.*?) \| URL: (.*?) \| Args: (.*)$",
                        line.strip(),
                    )
                    if match:
                        timestamp, ip_address, method, url, args = match.groups()
                        data.append({
                            "timestamp": timestamp,
                            "ip_address": ip_address,
                            "method": method,
                            "url": url,
                            "args": args,
                        })

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing HTTP URL log: {e}")
        return pd.DataFrame(columns=["timestamp", "ip_address", "method", "url", "args"])


def parse_http_creds_audits_log(http_audits_log_file):
    """Parse HTTP credentials log file, including rotated files."""
    try:
        data = []
        base_dir = str(Path(http_audits_log_file).parent)
        log_files = glob.glob(f"{base_dir}/http_audits.log*")
        
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    match = re.match(
                        r"(.*?) Client (.*?) attempted login with username: (.*?) and password: (.*?)$",
                        line.strip(),
                    )
                    if match:
                        timestamp, ip_address, username, password = match.groups()
                        data.append({
                            "timestamp": timestamp,
                            "ip_address": ip_address,
                            "username": username,
                            "password": password
                        })
        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing HTTP credentials log: {e}")
        return pd.DataFrame(columns=["timestamp", "ip_address", "username", "password"])


# Calculator to generate top 10 values from a dataframe. Supply a column name, counts how often each value occurs, stores in "count" column, then return dataframe with value/count.
def top_10_calculator(dataframe, column, truncate=False, max_length=30):
    """Calculate top 10 values from a column."""
    if dataframe.empty or column not in dataframe.columns:
        return pd.DataFrame({column: ["No Data"], "frequency": [0]})

    # Get value counts and convert to DataFrame with proper column names
    counts = dataframe[column].value_counts().head(10)
    result = pd.DataFrame({column: counts.index, "frequency": counts.values})
    
    # Truncate values if requested (e.g., for URLs)
    if truncate:
        result[column] = result[column].apply(lambda x: truncate_text(str(x), max_length))

    return result


# Helper function to truncate long strings
def truncate_text(text, max_length=30):
    """Truncate text and add ellipsis if needed"""
    return text if len(text) <= max_length else text[:max_length] + "..."


# Cache for country code lookups
country_code_cache = {}

@lru_cache(maxsize=1000)
def get_country_code(ip):
    """Takes an IP address as string type, uses the Cleantalk API to look up IP Geolocation.
    Results are cached to avoid repeated API calls."""
    if ip in country_code_cache:
        return country_code_cache[ip]

    data_list = []
    url = f"https://api.cleantalk.org/?method_name=ip_info&ip={ip}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get("data", {})
            country_info = ip_data.get(ip, {})
            result = [{"IP Address": ip, "Country_Code": country_info.get("country_code")}]
            country_code_cache[ip] = result
            return result
        elif response.status_code == 429:
            print(f"[!] CleanTalk Rate Limit hit for IP {ip}")
            return None
        else:
            print(f"[!] Error: Unable to retrieve data for IP {ip}. Status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"[!] Request failed for IP {ip}: {e}")
        return None

def ip_to_country_code(dataframe):
    """Convert IP addresses to country codes using the CleanTalk API with caching"""
    if dataframe.empty or "ip_address" not in dataframe.columns:
        print("[DEBUG] Empty dataframe or no ip_address column found")
        return pd.DataFrame(columns=["Country_Code", "frequency"])

    ip_counts = dataframe["ip_address"].value_counts().to_dict()
    country_counts = {}

    try:
        unique_ips = dataframe["ip_address"].unique()
        print(f"[DEBUG] Processing {len(unique_ips)} unique IPs")
        
        for ip in unique_ips:
            if ip == "127.0.0.1" or ip == "localhost":
                continue

            try:
                get_country = get_country_code(ip)
                if get_country and len(get_country) > 0:
                    country_code = get_country[0].get("Country_Code")
                    if country_code and isinstance(country_code, str) and country_code not in ("Unknown", "Error", ""):
                        print(f"[DEBUG] IP {ip} -> {country_code}")
                        country_counts[country_code] = country_counts.get(country_code, 0) + ip_counts[ip]
            except Exception as e:
                print(f"[DEBUG] Error processing IP {ip}: {e}")
                continue

        if not country_counts:
            return pd.DataFrame(columns=["Country_Code", "frequency"])

        country_df = pd.DataFrame([
            {"Country_Code": country, "frequency": count}
            for country, count in country_counts.items()
        ])

        if not country_df.empty:
            country_df = country_df.sort_values("frequency", ascending=False)
            print(f"[DEBUG] Created country code table with {len(country_df)} entries:")
            print(country_df)
            
        return country_df.reset_index(drop=True)

    except Exception as e:
        print(f"[ERROR] Error in ip_to_country_code: {e}")
        import traceback
        print(traceback.format_exc())
        return pd.DataFrame(columns=["Country_Code", "frequency"])
