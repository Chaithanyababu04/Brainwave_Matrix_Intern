import re
import json #converting dictionary -> string, here the final report is a dictionary, so to use regex properly, this needs to convert into --> string
import virustotal_python
import pprint
from base64 import urlsafe_b64encode
import argparse
import requests
print(''' o
o      ______/~/~/~/__           /((
  o  // __            ====__    /_((
 o  //  @))       ))))      ===/__((
    ))           )))))))        __((
    \\     \)     ))))    __===\ _((
     \\_______________====      \_((
                                 \((
# CREDITS: ASCII_ART ARCHIEVE
''')
# Parsing command line options
parser = argparse.ArgumentParser(description="Check URL using VirusTotal API")
parser.add_argument("-u", "--url", required=True, help="Enter the URL of the domain to check using VirusTotal module")
args = parser.parse_args()
url = args.url

# Interacting with VirusTotal API
with virustotal_python.Virustotal("<<ENTER YOUR VIRUS_TOTAL_API>>") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        Final_data = report.data
        pprint.pp(Final_data)
        final_string_data = json.dumps(Final_data)
        pattern = re.compile(r'(\W(?:malicious|suspicious)\W\:)(\W\d)')
        matches = pattern.finditer(final_string_data)
        print("VIRUS-TOTAL REPORT")
        for match in matches:
            print(match.group(1), int(match.group(2)))
            if int(match.group(2)) > 0:
                print("THIS IS A PHISHING-URL")
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")

def get_files(url):
    responce = requests.get(url)
    byte_data = responce.content
    string_data = byte_data.decode()
    print(string_data)
    pattern = re.compile(r'\w*(?:\.png|\.json|\.com|\.exe|\.msi|\.xml)')
    matches = pattern.finditer(string_data)
    for match in matches:
        print(match.group(0))

get_files(url)
'''
references:
https://docs.python.org/3/library/optparse.html
https://nanonets.com/blog/web-scraping-with-python-tutorial/
https://github.com/mitchellkrogza/Phishing.Database/tree/master?tab=readme-ov-file
https://docs.python.org/3/library/pprint.html
https://pypi.org/project/virustotal-python/
https://iris.unitn.it/retrieve/e3835197-3d91-72ef-e053-3705fe0ad821/ly2020typosquatting.pdf
'''
