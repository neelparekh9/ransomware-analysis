import json
import os
import pandas as pd

def load_cuckoo_report(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def analyze_ransomware_behavior(report):
    analysis = {}

    if 'behavior' in report:
        behavior_analysis = {}
        processes = report['behavior'].get('processes', [])
        behavior_analysis['total_processes'] = len(processes)
        behavior_analysis['process_names'] = [proc.get('process_name', 'N/A') for proc in processes]

        analysis['behavior'] = behavior_analysis

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

def save_to_excel(analysis_results, excel_file_path):
    df = pd.DataFrame(analysis_results)
    df = df.transpose()  # Transpose DataFrame for better formatting
    df.to_excel(excel_file_path, sheet_name='RansomwareAnalysis', index_label='Report')

def save_process_names(process_names, excel_file_path):
    process_df = pd.DataFrame(process_names, columns=['Process Names'])
    process_df.to_excel(excel_file_path, sheet_name='ProcessNames', index=False)

# Specify the base path where the reports are located
base_path = '/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports'

# Specify the number of reports to iterate through
num_reports = 210

analysis_results = process_multiple_files(base_path, num_reports)

# Extract total_processes and process_names
process_data = []
all_process_names = []

for i, result in enumerate(analysis_results, start=1):
    total_processes = result.get(f'Report{i}', {}).get('behavior', {}).get('total_processes', 0)
    process_data.append({'Report Number': i, 'Processes': total_processes})
    
    process_names = result.get(f'Report{i}', {}).get('behavior', {}).get('process_names', [])
    all_process_names.extend(process_names)

# Save the analysis results to Excel
#save_to_excel(analysis_results, 'bh_output_table.xlsx')

# Save process names to a separate Excel file
save_process_names(all_process_names, 'bh_process_names.xlsx')

# Display the process_data DataFrame
process_df = pd.DataFrame(process_data)
process_df.to_excel("bh_output_table.xlsx")
print(process_df)
