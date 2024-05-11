import requests
import pandas
import os

# The Program will not work if the Quota is Excceeded in the Free API (500 Lookups a Day)
# Using the Free API
api_key = "4d9049854df6fc33acb24daf429e1c036bad5b2de61485e5c8a17ca3d72d818a"

# Check If the File Exists
while True:
    try:
        file_path = input("Please Enter The File Path: ")
        # If the File Exists and it has a CSV File Extension
        if os.path.exists(file_path) and file_path.find('.csv', -4) != -1:
            break
    except FileExistsError:
        pass
    if not os.path.exists(file_path): print("File Does Not Exist")
    if file_path.find('.csv', -4) == -1: print("File Is Not CSV")
        
# Extract the CSV 
domain_csv = pandas.read_csv(file_path)
urls = domain_csv['Domain'].tolist()

# Create an empty list to record the scan IDs for URLs in the spreadsheet
report_urls = []

for i in urls:
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": i }
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": api_key
    }

    # Fetch the scan ID for a specific URL and append it to the report_urls list
    response = requests.post(url, data=payload, headers=headers)
    response_json = response.json()

    if "data" in response.json():
        report_urls.append(response_json['data']['links']['self'])

# Iterate over each of the scan IDs to obtain the report associated with each URL
for url in report_urls:
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    response_json = response.json()

    # add to Malicious URL Text File if there are three or more sources marking link as malicious
    number_flag_malicious = response_json['data']['attributes']['stats']['malicious']
    if number_flag_malicious >= 3:
        print("Malicious URL:", response_json['meta']['url_info']['url'])
        with open('VirusTotal_Malicious_Links.txt', 'a') as maliciouslinks:
            # Include Statistics
            for k,v in response_json['data']['attributes']['stats'].items():
                print(f"{k}: {v}")
                maliciouslinks.write(f"\n{k}: {v}")
            maliciouslinks.write(response_json['meta']['url_info']['url'])
            maliciouslinks.write("\n\n")
        print()

    # else, add to Safe URL Text File
    else:
        print("Safe URL:", response_json['meta']['url_info']['url'])
        with open('VirusTotal_Safe_Links.txt', 'a') as safelinks:
            # Include Statistics
            for k,v in response_json['data']['attributes']['stats'].items():
                print(f"{k}: {v}")
                safelinks.write(f"\n{k}: {v}")
            safelinks.write(response_json['meta']['url_info']['url']) 
            safelinks.write("\n\n")
        print()
