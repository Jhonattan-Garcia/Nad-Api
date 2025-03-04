import json
import requests
import os
from datetime import datetime

def read_config(filepath='config.json'):
    """
    Reads the configuration file and retrieves the VirusTotal API key and output settings.
    """
    try:
        with open(filepath, 'r') as file:
            config = json.load(file)
            return config.get("VirusTotalKey", ""), config.get("output_folder", "./results"), config.get("output_tittle", "Results_Search")
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: Invalid or missing config.json.")
        return "", "./results", "Results_Search"

def read_search_criteria(filepath='criteria.json'):
    """
    Reads the criteria.json file and retrieves search criteria.
    """
    try:
        with open(filepath, 'r') as file:
            criteria = json.load(file)
            return criteria.get("search_criteria", [])
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: Invalid or missing criteria.json.")
        return []

def search_virustotal(api_key, query):
    """
    Queries VirusTotal for domain or IP information.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{query}"  # For domains
    headers = {"x-apikey": api_key}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Request error: {response.status_code}, {response.text}")
        return {}

def format_timestamp(timestamp):
    """
    Converts a Unix timestamp to MM-DD-YY hh:mm:ss format.
    """
    if isinstance(timestamp, int):
        return datetime.utcfromtimestamp(timestamp).strftime("%m-%d-%y %H:%M:%S")
    return "N/A"

def main():
    api_key, output_folder, output_title = read_config()
    if not api_key:
        print("No valid API key found for VirusTotal.")
        return
    
    criteria = read_search_criteria()
    if not criteria:
        print("No search criteria found in criteria.json.")
        return
    
    all_results = {}
    fixed_results = []
    
    for item in criteria:
        query = item.get("value")
        if query:
            print(f"Querying VirusTotal for: {query}")
            results = search_virustotal(api_key, query)
            if results:
                all_results[query] = results
                
                # Extract only required fields for fixed results file
                data_attributes = results.get("data", {}).get("attributes", {})
                fixed_results.append({
                    "search_criteria": query,
                    "last_analysis_date": format_timestamp(data_attributes.get("last_analysis_date")),
                    "creation_date": format_timestamp(data_attributes.get("creation_date"))
                })
    
    if all_results:
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        
        # Save dynamic file with timestamp
        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        output_file = os.path.join(output_folder, f"{output_title}-VirusTotal-{timestamp}.json")
        with open(output_file, 'w') as file:
            json.dump(all_results, file, indent=4)
        print(f"Results saved in {output_file}")
        
        # Save fixed results file
        fixed_file = os.path.join(output_folder, "Current_VT_results.json")
        with open(fixed_file, 'w') as file:
            json.dump(fixed_results, file, indent=4)
        print(f"Fixed results saved in {fixed_file}")
    else:
        print("No valid results found.")

if __name__ == "__main__":
    main()