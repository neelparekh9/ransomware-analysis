import os
import json
import pandas as pd

def process_multiple_files(base_path, num_reports):
    results = []

    for i in range(1, num_reports + 1):
        file_path = os.path.join(base_path, f'report{i}.json')

        if os.path.exists(file_path):
            severity, analysis_id = extract_severity_and_id(file_path)
            results.append({'Filename': f'report{i}.json', 'Severity Score': severity, 'Analysis ID': analysis_id})
        else:
            print(f"File not found: {file_path}")

    return results

def extract_severity_and_id(json_file_path):
    with open(json_file_path, 'r') as file:
        data = json.load(file)
        severity_score = data["info"]["score"]
        analysis_id = data["info"]["id"]
    return severity_score, analysis_id

# Example usage
base_path = '/Users/neelparekh/Documents/PyCode/JSON Reports/json_reports'
num_reports = 210  # Change this to the actual number of reports

results = process_multiple_files(base_path, num_reports)

# Convert results to a DataFrame
df = pd.DataFrame(results)

# Save DataFrame to an Excel file
excel_output_path = 'severity.xlsx'
df.to_excel(excel_output_path, index=False)

print(f"Results saved to {excel_output_path}")
