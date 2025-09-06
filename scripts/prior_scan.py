import select
import subprocess
from pathlib import Path
import ipaddress
import json
import os
from collections import defaultdict
import time
from datetime import datetime
import tempfile
import shutil
from extract_prior_results import extract_prior_results
import itertools

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

def IPv6_network(ip, mask):
    network = ipaddress.IPv6Network(f"{ip}/{mask}", strict=False)
    return network

def get_scan_plan(filter_file:Path, list_file:Path, result_path:Path, precidt_port_num):
    
    net_filters = defaultdict(set)
    with open(filter_file, 'r') as f:
        for line in f:
            data = line.strip('\n').split(",")
            p = data[0]
            net = data[1]
            net_filters[net].add(p)
    # print(len(net_filters))

    filters = defaultdict(list)
    for networks, ports in net_filters.items():
        ports_list = list(ports)
        for i in range(0,min(precidt_port_num,len(ports)),1):
            port = ports_list[i]
            filters[port].append(networks)

        # port_num = len(ports)
        # if port_num > precidt_port_num:
        #     new_set = set(itertools.islice(ports, precidt_port_num))
        #     net_filters[networks] = new_set
    #     port_num = len(net_filters[networks])
    #     if port_num > max_port_num:
    #         max_port_num = port_num
    # print(f'max port num, min port mun,{max_port_num},{min_port_num}')
    # max port num, min port mun,16,1

    nets = defaultdict(list)
    with open(list_file, 'r') as f:
        for line in f:
            ip = line.strip('\n')
            net = IPv6_network(ip, '48')
            nets[str(net)].append(ip)
    
    for port, networks in filters.items():
        port_dir = result_path / port
        ip_list = []
        for net in networks:
            ip_list.extend(nets.get(net, []))

        if ip_list == []:
            continue
        Path.mkdir(port_dir, parents=True, exist_ok=True)
        with open(port_dir / "list", "w") as f:
            f.writelines(line + "\n" for line in ip_list)
        os.system(f"shuf -o {port_dir / 'list'} {port_dir / 'list'}")

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
    services_num = defaultdict(int)
    for port_dir in result_path.iterdir():
        if port_dir.is_dir():
            success_num = 0
            success_num += process_zgrab_json(port_dir / "zgrab-result", services_num)
            success_num += process_zgrab_json(port_dir / "zgrab-result-2", services_num)
            total_open_ports += count_file_lines(port_dir / "lzr-result")
            total_open_ports += count_file_lines(port_dir / "unknown-list")
            scan_ports_num += count_file_lines(port_dir / "list")
    
    for key, value in services_num.items():
        summary_file.write(f"{key},{value}\n")
        total_success += int(value)

    summary_file.write(f"Total,{total_success}\n")
    summary_file.write(f"open_ports-scan_ports,{total_open_ports},{scan_ports_num}\n")
    summary_file.close()
    
def process_zgrab_json(grab_results, services_num:dict):

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
                                services_num[multi_figerprint_map[module]] += 1
                            else:
                                services_num[module] += 1

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

def process_all_json_noraml(result_path:Path):

    summary_file = open(result_path / "summary", "w")
    total_success = 0
    total_open_ports = 0
    scan_ports_num = 0
    serivices_num = defaultdict(int)
    for port_dir in result_path.iterdir():
        if port_dir.is_dir():
            total_success += process_zgrab_json(port_dir / "zgrab-result", serivices_num)
            scan_ports_num += count_file_lines(port_dir / "list")
            total_open_ports += count_file_lines(port_dir / "open-list")
    
    for key, value in serivices_num.items():
        summary_file.write(f"{key},{value}\n")

    summary_file.write(f"Total,{total_success}\n")
    summary_file.write(f"total_open_ports,scan_ports_num,{total_open_ports},{scan_ports_num}\n")
    summary_file.write(f"Port Hit Rate,{total_open_ports / scan_ports_num}\n")
    summary_file.close()

def count_file_lines(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        line_count = sum(1 for line in lines if line.strip()) 

    return line_count

def Scan(scan_dir:Path, filter_file, type):
    
    # print('Prepare for Scanning...')
    # date_str = datetime.now().strftime("%Y-%m-%d")
    # Path.mkdir(scan_dir / date_str, parents=True, exist_ok=True)
    # result_path = scan_dir / date_str
    # logfile = open(result_path / 'scan_time', "w")

    # get_scan_plan(filter_file, scan_dir / 'list', result_path, 10)

    # print('Scanning...')
    # total_scan_time = 0
    # for port_dir in result_path.iterdir():
    #     if port_dir.is_dir():
    #         port = port_dir.name
    #         port_dir = result_path / str(port)
  
    #         command = ["sudo", "xmap", type, "-M", "tcp_syn", "-R", "5000", "-O", "csv", "-F", "success = 1 && repeat = 0", "-f", "saddr,sport", "-I", str(port_dir / "list"), "-o", str(port_dir / "xmap-result"), "-p", port]
            
    #         time0 = time.time()
    #         execute_command(command)
    #         time1 = time.time()
            
    #         os.system(f"sed 's/,.*//' {str(port_dir / 'xmap-result')} > {str(port_dir / 'open-list')}")
    #         os.system(f"sed -i '1d' {str(port_dir / 'open-list')}")
    #         print()

    #         command = ["zgrab2", "-f", str(port_dir / "open-list"), "-o", str(port_dir / "zgrab-result")]

        
    #         # generate_port_configs(port, scan_dir / 'etc' / 'all.ini', port_dir)
    #         # time0 = time.time()
    #         # execute_command(['./scan-v6.sh', 'ens33', str(port), str(scan_dir / 'list'), str(port_dir / 'lzr-result'), str(port_dir / 'multiple.ini'), str(port_dir / 'zgrab-result')])
    #         # time1 = time.time()
    #         # print()

    #         # process_lzr_json(port_dir / 'lzr-result', port_dir)

    #         # command = ["zgrab2", "-f", str(port_dir / "unknown-list"), "-o", str(port_dir / "zgrab-result-2")]
            
    #         if service_set.get(port_dir.name) is not None:
    #             command.extend(service_set[port_dir.name])
    #         else:
    #             command.extend(["banner", "-p", port_dir.name])

    #         time2 = time.time()
    #         execute_command(command)
    #         time3 = time.time()
    #         total_scan_time += int(time3-time2+time1-time0)
    #         print()
        
    # logfile.write(f"Total Scan Time: {total_scan_time // 3600} hours, {(total_scan_time % 3600) // 60} minutes, {total_scan_time % 60} seconds\n")
    # logfile.close()

    # print('Scanning Over!')
    # print('Processing results...')
    # process_all_json(result_path, scan_dir)
    # process_all_json_noraml(result_path)
    process_all_json_noraml(scan_dir / '2025-01-12-new')
    # extract_prior_results(result_path)
    print('Processing Over!')

if __name__ == "__main__":

    scan_path = Path("../Scan_Result/prior_scan/")
    filter_file = Path("../Predict_Result/priors_scan_48.csv")
    Scan(scan_path, filter_file, '-6')

