#/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports
import json
import os
import pandas as pd

def load_cuckoo_report(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def analyze_ransomware_behavior(report, report_number):
    analysis = {'report_number': report_number}

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
            network_analysis['tcp_connections'] = report['network']['tcp']
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
            ransomware_analysis = analyze_ransomware_behavior(cuckoo_report, i)
            result.append(ransomware_analysis)
        else:
            print(f"File not found: {file_path}")

    return result

# Specify the base path where the reports are located
base_path = '/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports'

# Specify the number of reports to iterate through
num_reports = 2

analysis_results = process_multiple_files(base_path, num_reports)

# Create DataFrames
http_dns_df = pd.DataFrame({
    'Report Number': [result['report_number'] for result in analysis_results],
    'http_requests': [result['network'].get('total_http_requests', 0) for result in analysis_results],
    'dns_requests': [result['network'].get('total_dns_requests', 0) for result in analysis_results],
})

connections_tcp_df = pd.DataFrame()
connections_udp_df = pd.DataFrame()
dns_request_details_df = pd.DataFrame()

for result in analysis_results:
    report_number = result['report_number']
    
    if 'tcp' in result['network']:
        connections_tcp_df = pd.concat([
            connections_tcp_df,
            pd.DataFrame({
                'Report Number': [report_number] * len(result['network']['tcp']),
                'src': [conn['src'] for conn in result['network']['tcp']],
                'dst': [conn['dst'] for conn in result['network']['tcp']],
                'offset': [conn['offset'] for conn in result['network']['tcp']],
                'time': [conn['time'] for conn in result['network']['tcp']],
                'dport': [conn['dport'] for conn in result['network']['tcp']],
                'sport': [conn['sport'] for conn in result['network']['tcp']],
            })
        ], ignore_index=True)

    if 'udp' in result['network']:
        connections_udp_df = pd.concat([
            connections_udp_df,
            pd.DataFrame({
                'Report Number': [report_number] * len(result['network']['udp']),
                'src': [conn['src'] for conn in result['network']['udp']],
                'dst': [conn['dst'] for conn in result['network']['udp']],
                'offset': [conn['offset'] for conn in result['network']['udp']],
                'time': [conn['time'] for conn in result['network']['udp']],
                'dport': [conn['dport'] for conn in result['network']['udp']],
                'sport': [conn['sport'] for conn in result['network']['udp']],
            })
        ], ignore_index=True)

    if 'dns' in result['network']:
        dns_request_details_df = pd.concat([
            dns_request_details_df,
            pd.DataFrame({
                'Report Number': [report_number] * len(result['network']['dns']),
                'request': [dns['request'] for dns in result['network']['dns']],
                'type': [dns['type'] for dns in result['network']['dns']],
            })
        ], ignore_index=True)

print("HTTP and DNS Details:")
print(http_dns_df)

print("\nTCP Connections:")
print(connections_tcp_df)

print("\nUDP Connections:")
print(connections_udp_df)

print("\nDNS Request Details:")
print(dns_request_details_df)
