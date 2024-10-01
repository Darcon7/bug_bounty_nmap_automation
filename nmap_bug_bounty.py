import os
import subprocess
import socket
import csv
from datetime import datetime

# Function to clean and convert target name to a valid filename
def clean_target_name(target):
    return target.replace(".", "_").replace("/", "_")

# Function to create project directory structure and ensure unique project number
def create_project_directory(target_name):
    date_str = datetime.now().strftime("%Y-%m-%d")
    project_number = 1
    
    while True:
        project_name = f"{project_number:03d}_{target_name}_{date_str}"
        if not os.path.exists(project_name):
            break
        project_number += 1
    
    directories = [
        f'{project_name}/recon',
        f'{project_name}/vulnerabilities',
        f'{project_name}/reports'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f'Created directory: {directory}')
    
    return project_name

# Function to run an in-scope Nmap scan for bug bounty targets
def run_in_scope_nmap_scan(target_ip, target_name, project_name):
    clean_name = clean_target_name(target_name)
    
    nmap_txt_output_path = os.path.join(project_name, 'recon', f'{clean_name}_nmap_scan.txt')
    nmap_xml_output_path = os.path.join(project_name, 'recon', f'{clean_name}_nmap_scan.xml')
    nmap_html_output_path = os.path.join(project_name, 'recon', f'{clean_name}_nmap_scan.html')
    vuln_output_path = os.path.join(project_name, 'vulnerabilities', f'{clean_name}_nmap_vuln_scan.txt')
    
    print(f"Running Nmap scan for {target_ip} ({target_name})...")

    # Run Nmap scan with web vulnerability checks and report generation
    subprocess.run([
        'sudo', 'nmap', '-sS', '-sV', '-O', '-p 80,443', '--script',
        'http-sql-injection,http-xssed,http-stored-xss,http-enum,http-config-backup',
        target_ip,
        '-oN', nmap_txt_output_path,
        '-oX', nmap_xml_output_path
    ])
    
    # Convert XML to HTML for easier readability
    subprocess.run(['xsltproc', nmap_xml_output_path, '-o', nmap_html_output_path])

    # Run additional vulnerability checks using Nmap's Vulners script (optional)
    subprocess.run([
        'sudo', 'nmap', '-sV', '--script', 'vulners', '--script-args', 'mincvss=5.0', target_ip,
        '-oN', vuln_output_path
    ])
    
    print(f"Scan completed for {target_name}. Reports saved.")
    
    return nmap_txt_output_path, vuln_output_path

# Function to summarize the Nmap scan results
def summarize_nmap_report(nmap_txt_path):
    open_ports = []
    vulnerabilities = []
    
    with open(nmap_txt_path, 'r') as file:
        for line in file:
            if '/tcp' in line and 'open' in line:
                open_ports.append(line.strip())  # Save open port info
            
            if 'VULNERABLE:' in line:
                vulnerabilities.append(line.strip())  # Capture vulnerabilities found

    return open_ports, vulnerabilities

# Function to generate final summary report
def generate_final_report(project_name, target_reports):
    summary_path = os.path.join(project_name, 'reports', 'final_summary_report.txt')
    
    with open(summary_path, 'w') as summary_file:
        summary_file.write("Final Nmap Scan Summary\n")
        summary_file.write("=========================\n\n")
        
        for target, reports in target_reports.items():
            nmap_txt_path, vuln_txt_path = reports
            summary_file.write(f"Target: {target}\n")
            
            # Summarize Nmap report
            open_ports, vulnerabilities = summarize_nmap_report(nmap_txt_path)
            
            summary_file.write("Open Ports:\n")
            for port in open_ports:
                summary_file.write(f"  - {port}\n")
            
            summary_file.write("\nVulnerabilities:\n")
            if vulnerabilities:
                for vuln in vulnerabilities:
                    summary_file.write(f"  - {vuln}\n")
            else:
                summary_file.write("  - None found\n")
            
            summary_file.write("\n" + "="*50 + "\n")
    
    print(f"Final summary report generated at: {summary_path}")

# Function to extract IP addresses or domains from a CSV file
def parse_csv_for_targets(csv_file_path):
    targets = []
    with open(csv_file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:
                targets.append(row[0])  # Assuming the target is in the first column
    return targets

# Main execution
if __name__ == '__main__':
    # Path to your CSV file containing targets
    csv_file_path = 'scopes_for_khealth_at_2024-09-26_01_33_32_UTC.csv'
    
    # Parse the CSV file for targets
    targets = parse_csv_for_targets(csv_file_path)
    
    # Create project directory with timestamp and target details
    project_name = create_project_directory('khealth')
    
    # Dictionary to store the paths of reports for each target
    target_reports = {}

    # Loop through all the targets from the CSV and run the Nmap scan for each
    for target in targets:
        try:
            target_ip = socket.gethostbyname(target)
            print(f"Scanning {target} (IP: {target_ip})...")
            nmap_txt_output_path, vuln_output_path = run_in_scope_nmap_scan(target_ip, target, project_name)
            
            # Save the report paths for final summary
            target_reports[target] = (nmap_txt_output_path, vuln_output_path)
        
        except Exception as e:
            print(f"Failed to scan {target}: {e}")
    
    # Generate a final summary report
    generate_final_report(project_name, target_reports)
    
    print(f"All scans completed for targets listed in {csv_file_path}.")
