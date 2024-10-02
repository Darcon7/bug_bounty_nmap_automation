import os
import subprocess
import socket
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import Tk
from tkinter.filedialog import askopenfilename

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

# Function to run Sublist3r for subdomain enumeration
def run_sublist3r(domain, project_name):
    clean_name = clean_target_name(domain)
    sublist3r_output_path = os.path.join(project_name, 'recon', f'{clean_name}_subdomains.txt')
    
    print(f"Running Sublist3r for {domain}...")
    subprocess.run([
        'python3', 'Sublist3r/sublist3r.py', '-d', domain, '-o', sublist3r_output_path
    ])
    
    print(f"Sublist3r scan completed for {domain}. Subdomains saved.")
    return sublist3r_output_path

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
    try:
        with open(csv_file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:
                    targets.append(row[0])  # Assuming the target is in the first column
        print(f"Targets extracted from CSV: {targets}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
    return targets

# Function to run scan for a target
def run_scan_for_target(target, project_name):
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Scanning {target} (IP: {target_ip})...")
        sublist3r_output_path = run_sublist3r(target, project_name)
        nmap_txt_output_path, vuln_output_path = run_in_scope_nmap_scan(target_ip, target, project_name)
        return target, (nmap_txt_output_path, vuln_output_path)
    except Exception as e:
        print(f"Failed to scan {target}: {e}")
        return target, None

# Main execution
if __name__ == '__main__':
    # Prompt for target name
    target_name = input("Enter the target name: ")
    
    # Use tkinter to open a file dialog for selecting the CSV file
    Tk().withdraw()  # We don't want a full GUI, so keep the root window from appearing
    csv_file_path = askopenfilename(title="Select the CSV file containing targets", filetypes=[("CSV files", "*.csv")])
    
    # Parse the CSV file for targets if provided
    if csv_file_path:
        targets = parse_csv_for_targets(csv_file_path)
    else:
        targets = [target_name]
    
    # Create project directory with timestamp and target details
    project_name = create_project_directory(target_name)
    
    # Dictionary to store the paths of reports for each target
    target_reports = {}

    # Loop through all the targets and run the Nmap scan for each
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(run_scan_for_target, target, project_name): target for target in targets}
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result:
                    target, reports = result
                    if reports:
                        target_reports[target] = reports
            except Exception as e:
                print(f"Error processing target {target}: {e}")

    # Generate a final summary report
    generate_final_report(project_name, target_reports)
    print(f"All scans completed for targets listed in {csv_file_path}.")
