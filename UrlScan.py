import json
import requests
import os
from datetime import datetime

def read_config(filepath='config.json'):
    """
    Reads the configuration file and retrieves the UrlScan API key and output settings.
    """
    try:
        with open(filepath, 'r') as file:
            config = json.load(file)
            return config.get("UrlScanKey", ""), config.get("output_folder", "./results"), config.get("output_tittle", "Results_Search")
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

def search_urlscan(api_key, query):
    """
    Queries UrlScan for domain information.
    """
    url = f"https://urlscan.io/api/v1/search/?q=domain:{query}"
    headers = {"API-Key": api_key}
    
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
    if isinstance(timestamp, str):
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%m-%d-%y %H:%M:%S")
        except ValueError:
            return "N/A"
    return "N/A"

def main():
    api_key, output_folder, output_title = read_config()
    if not api_key:
        print("No valid API key found for UrlScan.")
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
            print(f"Querying UrlScan for: {query}")
            results = search_urlscan(api_key, query)
            if results:
                all_results[query] = results
                
                # Extract only required fields for fixed results file
                for entry in results.get("results", []):
                    task_info = entry.get("task", {})
                    page_info = entry.get("page", {})
                    fixed_results.append({
                        "search_criteria": query,
                        "task_url": task_info.get("url", "N/A"),
                        "task_time": format_timestamp(task_info.get("time")),
                        "page_status": page_info.get("status", "N/A"),
                        "screenshot": entry.get("screenshot", "N/A"),
                        "task_id": task_info.get("uuid", "N/A")
                    })
    
    if all_results:
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        
        # Save dynamic file with timestamp
        timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        output_file = os.path.join(output_folder, f"{output_title}-UrlScan-{timestamp}.json")
        with open(output_file, 'w') as file:
            json.dump(all_results, file, indent=4)
        print(f"Results saved in {output_file}")
        
        # Save fixed results file
        fixed_file = os.path.join(output_folder, "Current_UrlScan_results.json")
        with open(fixed_file, 'w') as file:
            json.dump(fixed_results, file, indent=4)
        print(f"Fixed results saved in {fixed_file}")
    else:
        print("No valid results found.")

if __name__ == "__main__":
    main()