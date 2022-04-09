import requests, json, urllib3
from jsontraverse.parser import JsonTraverseParser

# Turn off TLS warnings
urllib3.disable_warnings()

# Change These
base = "https://localhost:8834"
access_key = '****'
secret_key = '****'

# Paths
FOLDERS = '/folders'
SCANS = '/scans'
SCAN_ID = SCANS + '/{scan_id}'
HOST_ID = SCAN_ID + '/hosts/{host_id}'

# Request To Nessus
def request(url):
     url = base + url
     headers = {
         'Content-Type': 'application/json',
         'X-ApiKeys': 'accessKey={}; secretKey={}'.format(access_key, secret_key)
     }
     response = requests.get(url, headers=headers, verify=False)
     return response.json()

def get_folders():
    return request(FOLDERS)

def get_scans():
    return request(SCANS)

def get_scan(scan_id):
    return request(SCAN_ID.format(scan_id=scan_id))

def get_hostDetails(scan_id, host_id):
    return request(HOST_ID.format(scan_id=scan_id, host_id=host_id))

# Returns each vulnerability in the scan results line by line
def get_vulnerabilities(scan_id):
    result = request(SCAN_ID.format(scan_id=scan_id))
    json_string = json.dumps(result)
    parser = JsonTraverseParser(json_string)
    data = parser.traverse("vulnerabilities")
    for i in data:
        print(i)

# Returns Operating System, host-ip, host_start, host_end
def get_hostDetails_info(scan_id, host_id):
    result = request(HOST_ID.format(scan_id=scan_id, host_id=host_id))
    json_string = json.dumps(result)
    parser = JsonTraverseParser(json_string)
    data = parser.traverse("info")
    return data





