import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# import time
# import json
import pandas
import os
import base64

def url_to_base64(url):
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    response = requests.get(url)
    if response.status_code == 200:
        return base64.urlsafe_b64encode(response.content).decode('utf-8')
    else:
        return None

while True:
    try:
        file_path = input("Please Enter The File Path: ")
        if os.path.exists(file_path):
            break
    except FileExistsError:
        pass
    print("File Does Not Exist")

domain_csv = pandas.read_csv((file_path))

urls = domain_csv['Domain'].tolist()

# parameters = {'apikey': my_api_key, 'resource': urls}

base64list = []

for i in urls:
    # if not i.startswith("http://") or not i.startswith("https://"):
    #     i = 'http://' + i
    # parameters = {'apikey': my_api_key, 'resource': i}

    # payload = { "url": i }
    # url = "https://www.virustotal.com/api/v3/urls/"
    # headers = {
    #     "accept": "application/json",
    #     "x-apikey": "4d9049854df6fc33acb24daf429e1c036bad5b2de61485e5c8a17ca3d72d818a",
    #     "content-type": "application/x-www-form-urlencoded"
    # }

    # response = requests.post(url, data=payload, headers=headers)
    url_to_base64(i)
    base64_string = url_to_base64(i)
    if base64_string != None:
        base64list.append(base64_string)

for i in base64list:
    url = "https://www.virustotal.com/api/v3/urls/" + base64_string

    headers = {
        "accept": "application/json",
        "x-apikey": "4d9049854df6fc33acb24daf429e1c036bad5b2de61485e5c8a17ca3d72d818a",
    }
    response = requests.get(url, headers=headers)

    print(response.text)
    
    # if json_response['code'] == 'NotFoundError':
    if json_response['error']['code'] == 'NotFoundError': 
        with open('Unknown Links.txt', 'a')  as notfound:
            notfound.write(i) and notfound.write("\tNOT found: Requires Manual Scan\n")
    # elif json_response['code'] >= 1:
    else:
        if json_response['code'] <= 0:
            with open('VirusTotal_Clean_Links.txt', 'a')  as clean:
                clean.write(i) and clean.write("\t NOT Malicious \n")
        else:
            with open('VirusTotal_Malicious_Links.txt', 'a')  as malicious:
                malicious.write(i) and malicious.write("\t Malicious") and malicious.write("\t Domains Detected by   "+ str(json_response['positives']) + "  Solutions\n")

    # time.sleep(15)
