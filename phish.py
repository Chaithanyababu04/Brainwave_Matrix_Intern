import json
import re
import virustotal_python
from base64 import urlsafe_b64encode
import argparse
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # Importing 3D plot capabilities

# Parsing command line options
parser = argparse.ArgumentParser(description="Check URL using VirusTotal API")
parser.add_argument("-u", "--url", required=True, help="Enter the URL of the domain to check using VirusTotal module")
args = parser.parse_args()
url = args.url

# Interacting with VirusTotal API
api_key = "APIKEY"  # Replace with your actual API key
with virustotal_python.Virustotal(api_key) as vtotal:
    try:
        # Submitting URL for analysis
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Getting report
        report = vtotal.request(f"urls/{url_id}")
        final_data = report.data
        pprint(final_data)
        final_string_data = json.dumps(final_data)
        
        # Extracting and analyzing data
        pattern = re.compile(r'"(malicious|suspicious)": (\d+)')
        matches = pattern.findall(final_string_data)
        
        print("VIRUS-TOTAL REPORT")
        for match in matches:
            print(f"{match[0]}: {match[1]}")
            if int(match[1]) > 0:
                print("THIS IS A PHISHING URL")

        # Graphing results
        labels = [match[0] for match in matches]
        values = [int(match[1]) for match in matches]
        
        # Bar chart
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color='blue')
        plt.xlabel('Type')
        plt.ylabel('Count')
        plt.title('Phishing URL Detection - Bar Chart')
        plt.show()
        
        # Pie chart
        plt.figure(figsize=(8, 8))
        plt.pie(values, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140)
        plt.axis('equal')
        plt.title('Phishing URL Detection - Pie Chart')
        plt.show()
        
        # 3D bar plot
        fig = plt.figure(figsize=(10, 8))
        ax = fig.add_subplot(111, projection='3d')
        ax.bar3d(labels, values, [0] * len(values), 0.5, 0.5, values, color='blue')
        ax.set_xlabel('Type')
        ax.set_ylabel('Count')
        ax.set_zlabel('Value')
        ax.set_title('Phishing URL Detection - 3D Bar Plot')
        plt.show()
        
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")
