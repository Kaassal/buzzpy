# Import library dependencies.
import pandas as pd
import re
import requests
import glob

# This file parses the various log files. The log files have different "formats" or information provided, so needed to create unique parsers for each.
# Each of these parsers takes the log file, gathers the specific information provided in the log, then returns the data in columns/rows Pandas dataframe type.

# Update the log file name to match the new name in ssh_honeypot.py
creds_audits_log_file = 'log_files/audits.log'  # Updated to match the new name
cmd_audits_log_file = 'log_files/ssh_cmd_audits.log'  # Ensure consistency

# Update the parsers to read all rotated log files.
def parse_creds_audits_log(creds_audits_log_file):
    """Parse SSH credentials log file, including rotated files."""
    try:
        data = []
        # Use glob to find all matching log files, including rotated ones.
        log_files = glob.glob(creds_audits_log_file + '*')
        for log_file in log_files:
            with open(log_file, 'r') as file:
                for line in file:
                    # Parse log format: "Client 127.0.0.1 connection attempt username: user, password: abc123"
                    match = re.match(r'Client (.*?) connection attempt username: (.*?), password: (.*?)$', line.strip())
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
        log_files = glob.glob(cmd_audits_log_file + '*')
        for log_file in log_files:
            with open(log_file, 'r') as file:
                for line in file:
                    # Parse log format: "Command: {command} Client: {ip}"
                    match = re.match(r'Command: (.*?) Client: (.*?)$', line.strip())
                    if match:
                        command, ip = match.groups()
                        data.append({'Command': command, 'Client': ip})

        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing commands log: {e}")
        return pd.DataFrame(columns=['Command', 'Client'])

# Calculator to generate top 10 values from a dataframe. Supply a column name, counts how often each value occurs, stores in "count" column, then return dataframe with value/count.
def top_10_calculator(dataframe, column):
    """Calculate top 10 values from a column."""
    if dataframe.empty or column not in dataframe.columns:
        return pd.DataFrame({column: ['No Data'], 'frequency': [0]})
    
    # Get value counts and convert to DataFrame with proper column names
    counts = dataframe[column].value_counts().head(10)
    result = pd.DataFrame({
        column: counts.index,
        'frequency': counts.values
    })
    
    print(f"Debug - DataFrame columns for {column}:", result.columns.tolist())
    print(f"Debug - First row of data:", result.iloc[0] if not result.empty else "Empty DataFrame")
    
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
            ip_data = data.get('data', {})
            country_info = ip_data.get(ip, {})
            data_list.append({'IP Address': ip, 'Country_Code': country_info.get('country_code')})
        elif response.status_code == 429:
            print(api_data["error_message"])
            print(f"[!] CleanTalk IP->Geolocation Rate Limited Exceeded.\n Please wait 60 seconds or turn Country=False (default).\n {response.status_code}")
        else:
            print(f"[!] Error: Unable to retrieve data for IP {ip}. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")

    return data_list

# Takes a dataframe with the IP addresses, converts each IP address to country geolocation code.
def ip_to_country_code(dataframe):

    data = []

    for ip in dataframe['ip_address']:
        get_country = get_country_code(ip)
        parse_get_country = get_country[0]["Country_Code"]
        data.append({"IP Address": ip, "Country_Code": parse_get_country})
    
    df = pd.DataFrame(data)
    return df