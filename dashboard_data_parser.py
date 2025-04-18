# Import library dependencies.
import pandas as pd
import re
import requests
import glob

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
        # Use glob to find all matching log files, including rotated ones.
        log_files = glob.glob(creds_audits_log_file + "*")
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    # Parse log format: "Client 127.0.0.1 connection attempt username: user, password: abc123"
                    match = re.match(
                        r"Client (.*?) connection attempt username: (.*?), password: (.*?)$",
                        line.strip(),
                    )
                    if match:
                        ip_address, username, password = match.groups()
                        data.append([ip_address, username, password])

        return pd.DataFrame(data, columns=["ip_address", "username", "password"])
    except Exception as e:
        print(f"Error parsing credentials log: {e}")
        return pd.DataFrame(columns=["ip_address", "username", "password"])


def parse_cmd_audits_log(cmd_audits_log_file):
    """Parse SSH command log file, including rotated files."""
    try:
        data = []
        # Use glob to find all matching log files, including rotated ones.
        log_files = glob.glob(cmd_audits_log_file + "*")
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    # Parse log format: "Command: {command} Client: {ip}"
                    match = re.match(r"Command: (.*?) Client: (.*?)$", line.strip())
                    if match:
                        command, ip = match.groups()
                        data.append({"Command": command, "Client": ip})

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing commands log: {e}")
        return pd.DataFrame(columns=["Command", "Client"])


def parse_http_url_audits_log(http_url_audits_log_file):
    """Parse HTTP URL log file, including rotated files."""
    try:
        data = []
        # Use glob to find all matching log files, including rotated ones
        log_files = glob.glob(http_url_audits_log_file + "*")
        for log_file in log_files:
            with open(log_file, "r") as file:
                for line in file:
                    # Parse log format: "Client {ip} | Method: {method} | URL: {url} | Args: {args}"
                    match = re.match(
                        r".*?Client (.*?) \| Method: (.*?) \| URL: (.*?) \| Args: (.*)$",
                        line.strip(),
                    )
                    if match:
                        ip_address, method, url, args = match.groups()
                        data.append(
                            {
                                "ip_address": ip_address,
                                "method": method,
                                "url": url,
                                "args": args,
                            }
                        )

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing HTTP URL log: {e}")
        return pd.DataFrame(columns=["ip_address", "method", "url", "args"])


# Calculator to generate top 10 values from a dataframe. Supply a column name, counts how often each value occurs, stores in "count" column, then return dataframe with value/count.
def top_10_calculator(dataframe, column):
    """Calculate top 10 values from a column."""
    if dataframe.empty or column not in dataframe.columns:
        return pd.DataFrame({column: ["No Data"], "frequency": [0]})

    # Get value counts and convert to DataFrame with proper column names
    counts = dataframe[column].value_counts().head(10)
    result = pd.DataFrame({column: counts.index, "frequency": counts.values})

    print(f"Debug - DataFrame columns for {column}:", result.columns.tolist())
    print(
        f"Debug - First row of data:",
        result.iloc[0] if not result.empty else "Empty DataFrame",
    )

    return result


# Takes an IP address as string type, uses the Cleantalk API to look up IP Geolocation.
def get_country_code(ip):

    data_list = []
    # According to the CleanTalk API docs, API calls are rate limited to 1000 per 60 seconds.
    url = f"https://api.cleantalk.org/?method_name=ip_info&ip={ip}"
    try:
        response = requests.get(url)
        api_data = response.json()
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get("data", {})
            country_info = ip_data.get(ip, {})
            data_list.append(
                {"IP Address": ip, "Country_Code": country_info.get("country_code")}
            )
        elif response.status_code == 429:
            print(api_data["error_message"])
            print(
                f"[!] CleanTalk IP->Geolocation Rate Limited Exceeded.\n Please wait 60 seconds or turn Country=False (default).\n {response.status_code}"
            )
        else:
            print(
                f"[!] Error: Unable to retrieve data for IP {ip}. Status code: {response.status_code}"
            )
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")

    return data_list


# Takes a dataframe with the IP addresses, converts each IP address to country geolocation code.
def ip_to_country_code(dataframe):
    """Convert IP addresses to country codes using the CleanTalk API"""
    if dataframe.empty or 'ip_address' not in dataframe.columns:
        print("Warning: Empty dataframe or no ip_address column found")
        return pd.DataFrame(columns=['IP Address', 'Country_Code'])

    data = []
    
    try:
        unique_ips = dataframe['ip_address'].unique()
        for ip in unique_ips:
            try:
                get_country = get_country_code(ip)
                if get_country and len(get_country) > 0:
                    parse_get_country = get_country[0].get('Country_Code', 'Unknown')
                    data.append({
                        "IP Address": ip,
                        "Country_Code": parse_get_country if parse_get_country else 'Unknown'
                    })
                else:
                    print(f"Warning: No country data returned for IP {ip}")
                    data.append({"IP Address": ip, "Country_Code": "Unknown"})
            except Exception as e:
                print(f"Error processing IP {ip}: {e}")
                data.append({"IP Address": ip, "Country_Code": "Error"})
                
        df = pd.DataFrame(data)
        print(f"Created country code table with {len(df)} entries")
        return df
    except Exception as e:
        print(f"Error in ip_to_country_code: {e}")
        return pd.DataFrame(columns=['IP Address', 'Country_Code'])
