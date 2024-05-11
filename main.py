import requests
import pandas
import os

api_key = "4d9049854df6fc33acb24daf429e1c036bad5b2de61485e5c8a17ca3d72d818a"

while True:
    try:
        file_path = input("Please Enter The File Path: ")
        if os.path.exists(file_path):
            break
    except FileExistsError:
        pass
    print("File Does Not Exist")


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

    print(response_json['meta']['url_info']['url'])
    # Could also change ['stats'] to ['results'] for more detailed output
    for k,v in response_json['data']['attributes']['stats'].items():
        print(f"{k}: {v}")
