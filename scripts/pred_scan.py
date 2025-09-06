import select
import subprocess
from pathlib import Path
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import json
import os
from collections import defaultdict
import time
from datetime import datetime
import tempfile
import shutil

service_set = {
    "47808": ["bacnet"],
    "20000": ["dnp3"],
    "1911": ["fox"],
    "21": ["ftp"],
    "80": ["http"],
    "143": ["imap"],
    "993": ["imap", "--imaps", "-p", "993"],
    "631": ["ipp"],
    "502": ["modbus"],
    "27017": ["mongodb"],
    "1433": ["mssql"],
    "3306": ["mysql"],
    "123": ["ntp"],
    "1521": ["oracle"],
    "110": ["pop3"],
    "995": ["pop3", "--pop3s", "-p", "995"],
    "5432": ["postgres"],
    "6379": ["redis"],
    "102": ["siemens"],
    "445": ["smb"],
    "25": ["smtp"],
    "465": ["smtp", "--smtps", "-p", "465"],
    "22": ["ssh"],
    "23": ["telnet"],
    "443": ["tls"],
    "5672": ["amqp091"]
}

multi_figerprint_map = {
    'smtp(ftp-smtp)': 'smtp',
    'smtp(smtp-ftp)': 'smtp',
    'smtp(imap-smtp-ftp)': 'smtp',
    'smtp(smtp-ftp-imap)': 'smtp',
    'smtp(smtp-pop3)': 'smtp',
    'imap(pop3-imap)': 'imap',
    'imap(imap-pop3)': 'imap'
}

def get_scan_plan(filter_file, result_path:Path, precidt_port_num):

    port_set = set()
    scan_plan = defaultdict(set)
    with open(filter_file, "r") as f:
        while line := f.readline():
            if line.strip() == 'service':
                continue
            ip, port = line.strip().strip().rsplit(":", 1)
            
            # if len(port_set) == precidt_port_num and port not in port_set:
            #     continue
            port_set.add(port)
            scan_plan[port].add(ip)
    
    for key, value in scan_plan.items():
        port_dir = result_path / key
        Path.mkdir(port_dir, parents=True, exist_ok=True)
        with open(port_dir / "list", "w") as f:
            f.writelines(line + "\n" for line in value)

def execute_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        while True:
            readable, _, _ = select.select([process.stdout, process.stderr], [], [])

            for stream in readable:
                output = stream.readline().decode('utf-8')
                if output:
                    print(output.strip())

            if process.poll() is not None:
                break

        return_code = process.poll()
        if return_code != 0:
            print(f"\nCommand failed with return code {return_code}")
            
    except Exception as e:
        print(f"An error occurred: {e}")

def generate_port_configs(port, all_ini_path, output_dir:Path):

    with open(all_ini_path, 'r') as file:
        lines = file.readlines()
        
    output_file_path = output_dir / 'multiple.ini'
    
    with open(output_file_path, 'w') as new_file:
        for line in lines:
            if 'port=x' in line:
                new_line = line.replace('port=x', f'port={port}')
            else:
                new_line = line
            new_file.write(new_line)
    
    print(f'Generated {output_file_path}')

def process_lzr_json(lzr_results, port_dir:Path):
    
    success_num = 0
    unknown_services = []
    try:
        with open(lzr_results, 'r') as file:
          
            for line in file:
                try:
                    result = json.loads(line)
                    if result['fingerprint'] == 'unknown':
                        ip = result['saddr']
                        unknown_services.append(ip)
                    else:
                        success_num += 1
       
                except json.JSONDecodeError as e:
                    print(f"error parsing json: {e}")
                    continue

            if success_num > 0:
                print(f"success results found and saved to {lzr_results}")
            else:
                print("no success results found")

            with open(port_dir / 'unknown-list', 'w') as f:
                f.write('\n'.join(unknown_services) + '\n')
            print(f"Unkonwn results saved to {port_dir / 'unknown-list'}")

    except IOError as e:
        print(f"error opening raw file: {e}")

def process_all_json(result_path:Path, scan_dir:Path):

    summary_file = open(result_path / "summary", "w")
    total_success = 0
    total_open_ports = 0
    scan_ports_num = 0
    serivices_num = defaultdict(int)
    for port_dir in result_path.iterdir():
        if port_dir.is_dir():
            success_num = 0
            success_num += process_zgrab_json(port_dir / "zgrab-result", serivices_num)
            success_num += process_zgrab_json(port_dir / "zgrab-result-2", serivices_num)
            total_open_ports += count_file_lines(port_dir / "lzr-result")
            total_open_ports += count_file_lines(port_dir / "unknown-list")
            scan_ports_num += count_file_lines(port_dir / "list")
    
    for key, value in serivices_num.items():
        summary_file.write(f"{key},{value}\n")
        total_success += int(value)

    summary_file.write(f"Total,{total_success}\n")
    summary_file.write(f"open_ports-scan_ports,{total_open_ports},{scan_ports_num}\n")
    summary_file.close()
    
def process_zgrab_json(grab_results, serivices_num:dict):

    success_num = 0
    try:
        with open(grab_results, 'r') as file:
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', dir='.')
            temp_filename = temp_file.name
            success_results = []
            for line in file:
                try:
                    result = json.loads(line)
                    for module, data in result.get('data', {}).items():
                        if data.get('status') == 'success' and data['result']:
                            success_results.append(json.dumps(result))
                            success_num += 1
                            if '-' in module:
                                serivices_num[multi_figerprint_map[module]] += 1
                            else:
                                serivices_num[module] += 1

                            if len(success_results) >= 10000: 
                                temp_file.write('\n'.join(success_results) + '\n')
                                success_results = []
                            break
                        
                except json.JSONDecodeError as e:
                    print(f"error parsing json: {e}")
                    continue

            if success_results:
                temp_file.write('\n'.join(success_results) + '\n')

            temp_file.close() 

            if success_num > 0:
                print(f"success results found and saved to {grab_results}")
            else:
                print("no success results found")
            shutil.move(temp_filename, grab_results)
            os.chmod(grab_results, 0o777) 

    except IOError as e:
        print(f"error opening raw file: {e}")

    return success_num

def count_file_lines(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        line_count = sum(1 for line in lines if line.strip()) 

    return line_count

def Scan(scan_dir:Path, filter_file):
    
    print('Prepare for Scanning...')
    date_str = datetime.now().strftime("%Y-%m-%d")
    Path.mkdir(scan_dir / date_str, parents=True, exist_ok=True)
    result_path = scan_dir / date_str
    logfile = open(result_path / 'scan_time', "w")

    get_scan_plan(filter_file, result_path, 30)

    print('Scanning...')
    total_scan_time = 0
    for port_dir in result_path.iterdir():
        if port_dir.is_dir():
            port = port_dir.name
            generate_port_configs(port, scan_dir / 'etc/all.ini', port_dir)

            time0 = time.time()
            execute_command(['./scan-v6.sh', 'ens33', str(port), str(port_dir / 'list'), str(port_dir / 'lzr-result'), str(port_dir / 'multiple.ini'), str(port_dir / 'zgrab-result')])
            time1 = time.time()
            print()

            process_lzr_json(port_dir / 'lzr-result', port_dir)

            command = ["zgrab2", "-f", str(port_dir / "unknown-list"), "-o", str(port_dir / "zgrab-result-2")]
            if service_set.get(port_dir.name) is not None:
                command.extend(service_set[port_dir.name])
            else:
                command.extend(["banner", "-p", port_dir.name])

            time2 = time.time()
            execute_command(command)
            time3 = time.time()
            print()

            total_scan_time += int(time3-time2+time1-time0)
        
    logfile.write(f"Total Scan Time: {total_scan_time // 3600} hours, {(total_scan_time % 3600) // 60} minutes, {total_scan_time % 60} seconds\n")
    logfile.close()

    print('Scanning Over!')
    print('Processing results...')
    process_all_json(result_path, scan_dir)
    print('Processing Over!')

if __name__ == "__main__":

    # change the arguments for your environment
    scan_path = Path("../Scan_Result/pred_scan/")
    filter_file = Path("../Predict_Result/pred_scan_list.csv")
    Scan(scan_path, filter_file)

