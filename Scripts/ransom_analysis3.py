import json
import os

def load_cuckoo_report(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def analyze_ransomware_behavior(report):
    analysis = {}
    
    if 'network' in report:
        network_analysis = {}
        network_analysis['total_http_requests'] = len(report['network'].get('http', []))
        network_analysis['http_request_details'] = [{
            'uri': http.get('uri', 'N/A'),
            'method': http.get('method', 'N/A')
        } for http in report['network'].get('http', [])]

        network_analysis['total_dns_requests'] = len(report['network'].get('dns', []))
        network_analysis['dns_request_details'] = [{
            'request': dns.get('request', 'N/A'),
            'type': dns.get('type', 'N/A')
        } for dns in report['network'].get('dns', [])]

        # Adding more network details if available
        if 'tcp' in report['network']:
            network_analysis['tcp_connections'] = report['network']['dns'][0]['type']
        if 'udp' in report['network']:
            network_analysis['udp_connections'] = report['network']['udp']

        analysis['network'] = network_analysis


    return analysis

def process_multiple_files(base_path, num_reports):
    result = []
    for i in range(1, num_reports + 1):
        file_path = os.path.join(base_path, f'report{i}.json')
        if os.path.exists(file_path):
            cuckoo_report = load_cuckoo_report(file_path)
            ransomware_analysis = analyze_ransomware_behavior(cuckoo_report)
            result.append({f'Report{i}': ransomware_analysis})
        else:
            print(f"File not found: {file_path}")

    return result

# Specify the base path where the reports are located
base_path = '/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports'

# Specify the number of reports to iterate through
num_reports = 2

analysis_results = process_multiple_files(base_path, num_reports)

print(json.dumps(analysis_results, indent=4))
