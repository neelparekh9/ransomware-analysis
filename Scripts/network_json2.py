import json
import os
import pandas as pd

def load_cuckoo_report(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def extract_connections(connection_list):
    connections = []
    for conn in connection_list:
        connections.append({
            'src': conn.get('src', 'N/A'),
            'dst': conn.get('dst', 'N/A'),
            'offset': conn.get('offset', 'N/A'),
            'time': conn.get('time', 'N/A'),
            'dport': conn.get('dport', 'N/A'),
            'sport': conn.get('sport', 'N/A'),
        })
    return connections

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

        # Extracting all TCP connections
        if 'tcp' in report['network']:
            network_analysis['tcp_connections'] = extract_connections(report['network']['tcp'])

        # Extracting all UDP connections
        if 'udp' in report['network']:
            network_analysis['udp_connections'] = extract_connections(report['network']['udp'])

        analysis['network'] = network_analysis

    # Add severity score and ID to the analysis
    analysis['severity_score'] = report.get('info', {}).get('score', 'N/A')
    analysis['analysis_id'] = report_number

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
num_reports = 210

analysis_results = process_multiple_files(base_path, num_reports)

# Create DataFrames
http_dns_df = pd.DataFrame({
    'Report Number': [result['report_number'] for result in analysis_results],
    'Severity Score': [result['severity_score'] for result in analysis_results],
    'http_requests': [result['network'].get('total_http_requests', 0) for result in analysis_results],
    'dns_requests': [result['network'].get('total_dns_requests', 0) for result in analysis_results],
})

connections_tcp_df = pd.DataFrame()
connections_udp_df = pd.DataFrame()
dns_request_details_df = pd.DataFrame()

for result in analysis_results:
    report_number = result['report_number']
    
    if 'tcp_connections' in result['network']:
        connections_tcp_df = pd.concat([
            connections_tcp_df,
            pd.DataFrame(result['network']['tcp_connections']).assign(**{'Report Number': report_number, 'Severity Score': result['severity_score']}),
        ], ignore_index=True)

    if 'udp_connections' in result['network']:
        connections_udp_df = pd.concat([
            connections_udp_df,
            pd.DataFrame(result['network']['udp_connections']).assign(**{'Report Number': report_number, 'Severity Score': result['severity_score']}),
        ], ignore_index=True)

    if 'dns_request_details' in result['network']:
        dns_request_details_df = pd.concat([
            dns_request_details_df,
            pd.DataFrame(result['network']['dns_request_details']).assign(**{'Report Number': report_number, 'Severity Score': result['severity_score']}),
        ], ignore_index=True)

print("HTTP and DNS Details:")
print(http_dns_df)

print("\nTCP Connections:")
print(connections_tcp_df)

print("\nUDP Connections:")
print(connections_udp_df)

print("\nDNS Request Details:")
print(dns_request_details_df)

http_dns_df.to_excel("http_dns.xlsx", index=False)
connections_tcp_df.to_excel("tcp.xlsx", index=False)
connections_udp_df.to_excel("udp.xlsx", index=False)
dns_request_details_df.to_excel("dns_req.xlsx", index=False)
