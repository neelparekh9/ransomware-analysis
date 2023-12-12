import json
import os
import pandas as pd

def load_cuckoo_report(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def analyze_ransomware_behavior(report, report_number):
    analysis = {}

    if 'signatures' in report:
        signatures = report['signatures']
        total_signatures = len(signatures)
        highest_severity = max(sig.get('severity', 0) for sig in signatures) if total_signatures > 0 else 0

        analysis['signatures'] = {
            'total_signatures': total_signatures,
            'highest_severity': highest_severity,
            'signature_details': [{
                'name': sig.get('name', 'N/A'),
                'severity': sig.get('severity', 'N/A'),
                'description': sig.get('description', 'N/A')
            } for sig in signatures]
        }

    # Add severity score and ID to the analysis
    analysis['severity_score'] = report.get('info', {}).get('score', 'N/A')
    analysis['analysis_id'] = report_number

    return analysis

def process_multiple_files(base_path, num_reports):
    result = []
    all_signature_details = []

    for i in range(1, num_reports + 1):
        file_path = os.path.join(base_path, f'report{i}.json')
        if os.path.exists(file_path):
            cuckoo_report = load_cuckoo_report(file_path)
            ransomware_analysis = analyze_ransomware_behavior(cuckoo_report, i)

            # Append results for individual reports
            result.append({
                'Report Number': ransomware_analysis['analysis_id'],
                'Severity Score': ransomware_analysis['severity_score'],
                'Total Signatures': ransomware_analysis['signatures']['total_signatures'],
                'Highest Severity': ransomware_analysis['signatures']['highest_severity']
            })

            # Append all signature details to the list
            all_signature_details.extend(ransomware_analysis['signatures']['signature_details'])
        else:
            print(f"File not found: {file_path}")

    # Create a DataFrame for individual reports
    result_df = pd.DataFrame(result)

    # Create a DataFrame for all signature details
    all_signature_details_df = pd.DataFrame(all_signature_details)

    return result_df, all_signature_details_df

# Specify the base path where the reports are located
base_path = '/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports'

# Specify the number of reports to iterate through
num_reports = 210

try:
    individual_reports_df, all_signature_details_df = process_multiple_files(base_path, num_reports)

    # Export to Excel
    with pd.ExcelWriter('sig_output.xlsx', engine='xlsxwriter') as writer:
        individual_reports_df.to_excel(writer, sheet_name='Individual Reports', index=False)
        all_signature_details_df.to_excel(writer, sheet_name='All Signature Details', index=False)

    print("Excel export successful.")
except Exception as e:
    print(f"An error occurred: {e}")
