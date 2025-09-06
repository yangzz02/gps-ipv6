import json
import pyasn
from pathlib import Path
import os
import datetime
import re

asndb = pyasn.pyasn('./asn_db/ip6asn_db.dat')
def query(ip):
    asn, prefix = asndb.lookup(ip)
    return asn, prefix   

def extract_prior_results(result_path:Path):
    gps_results = []
    prior_results = open(result_path / 'prior_results', "w")

    for port_dir in result_path.iterdir():
        if port_dir.is_dir():
            try: 
                with open(port_dir / 'lzr-result', "r") as f1:
                    while line := f1.readline():
                        data = json.loads(line.strip())
                        ip = data['saddr']
                        if data.get('data') is None:
                            continue
                        asn, _ = query(ip)
                        if asn is None:
                            asn = ""
                        GPS_json_data = {
                            "ip": ip, 
                            "p": data['sport'], 
                            "asn": asn, 
                            "data": str(data['data']), 
                            "fingerprint": data['fingerprint'], 
                            "w": data['window']
                        }
                        gps_results.append(json.dumps(GPS_json_data))
                        if len(gps_results) >= 10000:
                            prior_results.write('\n'.join(gps_results) + '\n')
                            gps_results = []
            except:
                print('No lzr-result\n')

            extract_zgrab_data(port_dir / 'zgrab-result', gps_results, port_dir)
            if len(gps_results) >= 10000:
                prior_results.write('\n'.join(gps_results) + '\n')
                gps_results = []
            
            try:
                extract_zgrab_data(port_dir / 'zgrab-result-2', gps_results, port_dir)
                if len(gps_results) >= 10000:
                    prior_results.write('\n'.join(gps_results) + '\n')
                    gps_results = []
            except:
                print('No zgrab-result-2\n')

            
    if gps_results:
        prior_results.write('\n'.join(gps_results) + '\n')

    prior_results.close()

def get_service(data):
    service = next(iter(data['data']))
    return service

def extract_banner(service, data):
    banner = data['data'][service]['result']['banner'].strip()
    ip = data['ip']
    return ip, banner

def extract_ssh_data(service, data):
    ip = data['ip']

    ssh_info = data['data'][service]['result']
    
    # Extract SSH service version
    ssh_version = ssh_info['server_id']['raw']
    
    # Extract public key information
    kye_type = ssh_info['key_exchange']['server_signature']['parsed']['algorithm']
    public_key = ssh_info['key_exchange']['server_host_key']['raw']
    
    # Service public key fingerprint
    fingerprint_sha256 = ssh_info['key_exchange']['server_host_key']['fingerprint_sha256']
    
    # Extract Kex algorithms
    kex_algorithms = ssh_info['server_key_exchange']['kex_algorithms']
    
    # Extract Server Host Key Algorithms
    host_key_algorithms = ssh_info['server_key_exchange']['host_key_algorithms']
    
    # Extract Encryption Algorithms
    server_to_client_ciphers = ssh_info['server_key_exchange']['server_to_client_ciphers']
    
    # Extract MAC Algorithms
    server_to_client_macs = ssh_info['server_key_exchange']['server_to_client_macs']
    
    # Extract Compression Algorithms
    server_to_client_compression = ssh_info['server_key_exchange']['server_to_client_compression']
    
    banner = (
        "SSH Version: {ssh_version}\n"
        "Key Type: {key_type}\n"
        "Public Key: {public_key}\n"
        "Fingerprint_sha256: {fingerprint_sha256}\n"
        "Kex Algorithms:\n    {kex_algorithms}\n"
        "Server Host Key Algorithms:\n    {host_key_algorithms}\n"
        "Encryption Algorithms:\n    {server_to_client_ciphers}\n"
        "MAC Algorithms:\n    {server_to_client_macs}\n"
        "Compression Algorithms:\n    {server_to_client_compression}"
    ).format(
        ssh_version=ssh_version,
        key_type=kye_type,
        public_key=public_key,
        fingerprint_sha256=fingerprint_sha256,
        kex_algorithms=', '.join(kex_algorithms),
        host_key_algorithms=', '.join(host_key_algorithms),
        server_to_client_ciphers=', '.join(server_to_client_ciphers),
        server_to_client_macs=', '.join(server_to_client_macs),
        server_to_client_compression=', '.join(server_to_client_compression)
    )
    return ip, banner

def extract_http_data(service, data):
    ip = data['ip']

    response_data = data.get('data', {}).get(service, {}).get('result', {}).get('response', {})
    http_version = response_data.get('protocol', {}).get('name', 'HTTP/Unknown')
    status_line = response_data.get('status_line', 'No status line')
    headers = response_data.get('headers', {})

    body = response_data.get('body', '')
    body_sha256 = response_data.get('body_sha256', 'No body_sha256')

    title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
    title = title_match.group(1) if title_match else "No title found"

    response_headers = [f"{http_version} {status_line}"]
    response_headers += [f"{key.replace('_', '-').capitalize()}: {', '.join(value)}" 
                     for key, value in headers.items() if key != 'unknown']


    banner = "\n".join(response_headers)
    return ip, banner    

def extract_true_keys(d):
    if not d:
        return "N/A"
    true_keys = []
    for key, value in d.items():
        if value is True:
            formatted_key = key.replace('_', ' ').title()
            true_keys.append(formatted_key)
    return ", ".join(true_keys)
    
def extract_tls_data(service, data):
    ip = data.get("ip", "N/A")
    
    tls_data = data.get("data", {}).get(service, {})
    if tls_data.get("status") != "success":
        return ip, ""
    tls_handshake_log = tls_data.get("result", {}).get("handshake_log", {})
    tls_server_hello = tls_handshake_log.get("server_hello", {})
    tls_version = tls_server_hello.get("version", {}).get("name", "N/A")
    tls_cipher_suite = tls_server_hello.get("cipher_suite", {}).get("name", "N/A")
    tls_heartbeat = tls_server_hello.get("heartbeat", "N/A")
    
    cert_info = data.get("data", {}).get(service, {}).get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})
    version = cert_info.get("version", "N/A")
    serial_number = cert_info.get("serial_number", "N/A")
    signature_algorithm = cert_info.get("signature_algorithm", {}).get("name", "N/A")
    issuer_dn = cert_info.get("issuer_dn", "N/A")
    subject_dn = cert_info.get("subject_dn", "N/A")
    
    validity = cert_info.get("validity", {})
    not_before = validity.get("start", "N/A")
    not_after = validity.get("end", "N/A")
    
    key_alg = cert_info.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "N/A")
    subject_key_output = []
    if key_alg == "RSA":
        rsa_key_info = cert_info.get("subject_key_info", {}).get("rsa_public_key", {})
        public_key_size = rsa_key_info.get("length", "N/A")
        modulus = rsa_key_info.get("modulus", "N/A")
        exponent = rsa_key_info.get("exponent", "N/A")
        subject_key_output.append(f"Public Key Algorithm: {key_alg}")
        subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
        subject_key_output.append(f"  modulus: {modulus}")
        subject_key_output.append(f"  exponent: {exponent}")
    elif key_alg == "ECDSA":
        ecdsa_key_info = cert_info.get("subject_key_info", {}).get("ecdsa_public_key", {})
        public_key_size = ecdsa_key_info.get("length", "N/A")
        pub = ecdsa_key_info.get("pub", "N/A")
        curve =  ecdsa_key_info.get("curve", "N/A")
        subject_key_output.append(f"Public Key Algorithm: {key_alg}")
        subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
        subject_key_output.append(f"  pub: {pub}")
        subject_key_output.append(f"  curve: {curve}")

    extensions = cert_info.get("extensions", {})
    if extensions:
        key_usage = extensions.get("key_usage", {})
        extended_key_usage = extensions.get("extended_key_usage", {})
        
        basic_constraints = extensions.get("basic_constraints", {})
        def format_constraints(constraints):
            if not constraints:
                return "N/A"
            key_mapping = {
            "is_ca": "CA",
            "max_path_len": "Max Path Len"}
            formatted_output = []
            for key, value in constraints.items():
                if key in key_mapping:
                    formatted_key = key_mapping[key]
                    formatted_output.append(f"{formatted_key}: {value}")
            return ", ".join(formatted_output)
        
        subject_key_identifier = extensions.get("subject_key_id", "N/A")
        authority_key_identifier = extensions.get("authority_key_id", "N/A")

        certificate_policies = extensions.get("certificate_policies", [])
        def format_certificate_policies(policies):
            if not policies:
                return "N/A"
            formatted_output = []
            for policy in policies:
                policy_id = policy.get("id", "")
                formatted_output.append(f"Policy: {policy_id}")
                cps_list = policy.get("cps", [])
                for cps in cps_list:
                    formatted_output.append(f"CPS: {cps}") 
            return ", ".join(formatted_output)

        authority_info_access  = extensions.get("authority_info_access", {})
        def format_authority_info_access(authority_info_access):
            if not authority_info_access:
                return "N/A"
            output_lines = []
            if "issuer_urls" in authority_info_access:
                for url in authority_info_access["issuer_urls"]:
                    output_lines.append(f"CA Issuers - URI:{url}")
            if "ocsp_urls" in authority_info_access:
                for url in authority_info_access["ocsp_urls"]:
                    output_lines.append(f"OCSP - URI:{url}")
            return ", ".join(output_lines)

        subject_alternative_name = extensions.get("subject_alt_name", {}).get("dns_names", "N/A")
        signed_certificate_timestamps = extensions.get("signed_certificate_timestamps", [])
        def format_timestamp(timestamp):
            return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%b %d %H:%M:%S %Y UTC')
        def format_scts(scts):
            if not scts:
                return "    N/A"
            output_lines = []
            for sct in scts:
                output_lines.append("    Signed Certificate Timestamp:")
                output_lines.append(f"        Version  : {sct['version']}")
                output_lines.append(f"        Log ID   : {sct['log_id']}")
                output_lines.append(f"        Timestamp: {format_timestamp(sct['timestamp'])}")
                output_lines.append(f"        Signature: {sct['signature']}")
            return "\n\t".join(output_lines)
        extensions_banner = (
            """\
            Key Usage: 
                {extract_true_keys}
            Extended Key Usage: 
                {extract_true_keys}
            Basic Constraints: 
                {format_constraints}
            Subject Key Identifier: 
                {subject_key_identifier}
            Authority Key Identifier: 
                {authority_key_identifier}
            Certificate Policies:
                {format_certificate_policies}
            Authority Information Access: 
                {format_authority_info_access}
            Subject Alternative Name:
                {subject_alternative_name}
            CT Precertificate SCTs:
                {format_scts}
            """
        ).format(
            extract_true_keys=extract_true_keys(key_usage),
            format_constraints=format_constraints(basic_constraints),
            format_certificate_policies=format_certificate_policies(certificate_policies),
            format_authority_info_access=format_authority_info_access(authority_info_access),
            format_scts=format_scts(signed_certificate_timestamps),
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            basic_constraints=basic_constraints,
            subject_key_identifier=subject_key_identifier,
            authority_key_identifier=authority_key_identifier,
            certificate_policies=certificate_policies,
            authority_info_access=authority_info_access,
            subject_alternative_name=', '.join(subject_alternative_name) if subject_alternative_name != "N/A" else "N/A",
            signed_certificate_timestamps=signed_certificate_timestamps
        )
    signature = cert_info.get('signature', {})

    banner = (
        """\
    SSL Certificate
    Version: {tls_version}
    CipherSuit: {tls_cipher_suite}
    HeartBeat: {tls_heartbeat}
    Certificate Information:
        Version: {version}
        Serial Number: {serial_number}
        Signature Algorithm: {signature_algorithm}
        Issuer: {issuer_dn}
        Validity:
            Not Before: {not_before}
            Not After : {not_after}
        Subject: {subject_dn}
            {subject_key_output}
        X509v3 Extensions:
        {extensions_banner}
        Signature Algorithm: {signature_algorithm_name}
        Signature Value: {signature_value}
        Signature Self Signed: {signature_self_signed}\
    """
    ).format(
        tls_version=tls_version,
        tls_cipher_suite=tls_cipher_suite,
        tls_heartbeat=tls_heartbeat,
        version=version,
        serial_number=serial_number,
        signature_algorithm=signature_algorithm,
        issuer_dn=issuer_dn,
        not_before=not_before,
        not_after=not_after,
        subject_dn=subject_dn,
        subject_key_output='\n\t'.join(subject_key_output),
        extensions_banner=extensions_banner if extensions else 'N/A',
        signature_algorithm_name=signature['signature_algorithm']['name'],
        signature_value=signature['value'],
        signature_self_signed=signature['self_signed']
    )
    return ip, banner

def extract_sql_data(service, data):

    if service == 'mysql':
        protocol_version = data.get('data', {}).get(service, {}).get('result', {}).get('protocol_version', 'N/A')
        server_version = data.get('data', {}).get(service, {}).get('result', {}).get('server_version', 'N/A')
        status_flags = data.get('data', {}).get(service, {}).get('result', {}).get('status_flags', 'N/A')
        capability_flags = data.get('data', {}).get(service, {}).get('result', {}).get('capability_flags', 'N/A')
        sql_banner = (
            """\
        Protocol Version: {protocol_version}
        Server Version: {server_version}
        Status: 
            {status_flags}
        Capability:
            {capability_flags}
        """
        ).format(
            protocol_version=protocol_version,
            server_version=server_version,
            status_flags=extract_true_keys(status_flags) if isinstance(status_flags, dict) else status_flags,
            capability_flags=extract_true_keys(capability_flags) if isinstance(capability_flags, dict) else capability_flags
        )
    else:
        protocol_version = data.get('data', {}).get(service, {}).get('result', {}).get('version', 'N/A')
        encrypt_mode = data.get('data', {}).get(service, {}).get('result', {}).get('encrypt_mode', 'N/A')
        sql_banner = (
            "Protocol Version: {protocol_version}\n"
            "Encrypt Mode: {encrypt_mode}"
        ).format(
            protocol_version=protocol_version,
            encrypt_mode=encrypt_mode
        )

    tls_handshake_log = data.get("data", {}).get(service, {}).get("result", {}).get("tls", {}).get("handshake_log", {})
    SSL_banner = "    N/A"
    if tls_handshake_log:
        tls_server_hello = tls_handshake_log.get("server_hello", {})
        tls_version = tls_server_hello.get("version", {}).get("name", "N/A")
        tls_cipher_suite = tls_server_hello.get("cipher_suite", {}).get("name", "N/A")
        tls_heartbeat = tls_server_hello.get("heartbeat", "N/A")
        
        cert_info = data.get("data", {}).get(service, {}).get("result", {}).get("tls", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})
        version = cert_info.get("version", "N/A")
        serial_number = cert_info.get("serial_number", "N/A")
        signature_algorithm = cert_info.get("signature_algorithm", {}).get("name", "N/A")
        issuer_dn = cert_info.get("issuer_dn", "N/A")
        subject_dn = cert_info.get("subject_dn", "N/A")
        
        validity = cert_info.get("validity", {})
        not_before = validity.get("start", "N/A")
        not_after = validity.get("end", "N/A")
        
        key_alg = cert_info.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "N/A")
        subject_key_output = []
        if key_alg == "RSA":
            rsa_key_info = cert_info.get("subject_key_info", {}).get("rsa_public_key", {})
            public_key_size = rsa_key_info.get("length", "N/A")
            modulus = rsa_key_info.get("modulus", "N/A")
            exponent = rsa_key_info.get("exponent", "N/A")
            subject_key_output.append(f"Public Key Algorithm: {key_alg}")
            subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
            subject_key_output.append(f"  modulus: {modulus}")
            subject_key_output.append(f"  exponent: {exponent}")
        elif key_alg == "ECDSA":
            ecdsa_key_info = cert_info.get("subject_key_info", {}).get("ecdsa_public_key", {})
            public_key_size = ecdsa_key_info.get("length", "N/A")
            pub = ecdsa_key_info.get("pub", "N/A")
            curve =  ecdsa_key_info.get("curve", "N/A")
            subject_key_output.append(f"Public Key Algorithm: {key_alg}")
            subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
            subject_key_output.append(f"  pub: {pub}")
            subject_key_output.append(f"  curve: {curve}")

        signature = cert_info.get('signature', {})
        SSL_banner = (
            "Version: {tls_version}\n"
            "CipherSuit: {tls_cipher_suite}\n"
            "HeartBeat: {tls_heartbeat}\n"
            "Certificate Information:\n"
            "    Version: {version}\n"
            "    Serial Number: {serial_number}\n"
            "    Signature Algorithm: {signature_algorithm}\n"
            "    Issuer: {issuer_dn}\n"
            "    Validity:\n"
            "        Not Before: {not_before}\n"
            "        Not After : {not_after}\n"
            "    Subject: {subject_dn}\n"
            "        {subject_key_output}\n"
            "    Signature Algorithm: {signature_algorithm_name}\n"
            "    Signature Value: {signature_value}\n"
            "    Signature Self Signed: {signature_self_signed}"
        ).format(
            tls_version=tls_version,
            tls_cipher_suite=tls_cipher_suite,
            tls_heartbeat=tls_heartbeat,
            version=version,
            serial_number=serial_number,
            signature_algorithm=signature_algorithm,
            issuer_dn=issuer_dn,
            not_before=not_before,
            not_after=not_after,
            subject_dn=subject_dn,
            subject_key_output='\n\t'.join(subject_key_output),
            signature_algorithm_name=signature.get('signature_algorithm', {}).get('name', 'N/A'),
            signature_value=signature.get('value', 'N/A'),
            signature_self_signed=signature.get('self_signed', 'N/A')
        )

    banner = (
        "{sql_banner}\n"
        "SSL Certificate:\n"
        "{SSL_banner}"
    ).format(
        sql_banner=sql_banner,
        SSL_banner=SSL_banner
    )
    
    ip = data.get("ip", "N/A")
    return ip, banner

def extract_smb_data(service, data):
    ip = data.get("ip", "N/A")

    smb_data = data.get('data', {}).get(service, {}).get('result', {})
    if not smb_data:
        return ip, ""
    authentication = "enabled" if smb_data.get('has_ntlm') else "disabled"
    smb_version = smb_data.get('smb_version', {}).get('version_string', 'Unknown')
    os_info = smb_data.get('native_os', 'Unknown')
    if os_info == '':
        os_info = 'Unknown'
    
    capabilities = smb_data.get('smb_capabilities', {})
    capabilities_list = []
    if capabilities.get('smb_dfs_support'):
        capabilities_list.append('dfs-support')
    if capabilities.get('smb_leasing_support'):
        capabilities_list.append('leasing-support')
    if capabilities.get('smb_multicredit_support'):
        capabilities_list.append('multicredit-support')
    capabilities_str = ", ".join(capabilities_list) if capabilities_list else "N/A"

    banner = (
        "SMB Status:\n"
        "Authentication: {authentication}\n"
        "SMB Version: {smb_version}\n"
        "OS: {os_info}\n"
        "Capabilities: \n      {capabilities_str}"
    ).format(
        authentication=authentication,
        smb_version=smb_version,
        os_info=os_info,
        capabilities_str=capabilities_str
    )
    return ip, banner

def format_dict(d):
    if not d:
        return "N/A"
    formatted_output = []
    for key, value in d.items():
        if isinstance(value, list):
            value_str = ", ".join(value)
            formatted_output.append(f"{key}: {value_str}")
        elif isinstance(value, dict):
            value_str = format_dict(value)
            formatted_output.append(f"{key}:")
            formatted_output.append("\n  ".join(value_str.splitlines()))
        else:
            formatted_output.append(f"{key}: {value}")   
    return "\n    ".join(formatted_output)

def extract_oracle_data(service, data):
    ip = data.get("ip", "N/A")

    accept_version = data['data'].get(service, {}).get('result', {}).get('handshake', {}).get('accept_version', 'N/A')
    if accept_version == 0:
        refuse_version = data['data'].get(service, {}).get('result', {}).get('handshake', {}).get('refuse_version', 'N/A')
        refuse_error_raw = data['data'].get(service, {}).get('result', {}).get('handshake', {}).get('refuse_error_raw', 'N/A')
        banner = f"Refuse Version: {refuse_version}\nRefuse Error Raw: {refuse_error_raw}"
    else:
        global_service_options = data['data'].get(service, {}).get('result', {}).get('handshake', {}).get('global_service_options', {})
        nsn_service_versions = data['data'].get(service, {}).get('result', {}).get('handshake', {}).get('nsn_service_versions', {})
        banner = (
            "Global Service Options:\n    {extract_true_keys}\n"
            "NSN Service Versions:\n    {format_dict}"
        ).format(
            extract_true_keys=extract_true_keys(global_service_options),
            format_dict=format_dict(nsn_service_versions),
            global_service_options=global_service_options,
            nsn_service_versions=nsn_service_versions
        )
    
    return ip, banner

def extract_postgres_data(service, data):
    supported_versions = data['data'].get(service, {}).get('result', {}).get('supported_versions', 'N/A')
    protocol_error = data['data'].get(service, {}).get('result', {}).get('protocol_error', {})
    startup_error = data['data'].get(service, {}).get('result', {}).get('startup_error', {})
    is_ssl = data['data'].get(service, {}).get('result', {}).get('is_ssl', 'N/A')
    SSL_banner = "    N/A"
    if is_ssl:
        tls_handshake_log = data.get("data", {}).get(service, {}).get("result", {}).get("tls", {}).get("handshake_log", {})
        tls_server_hello = tls_handshake_log.get("server_hello", {})
        tls_version = tls_server_hello.get("version", {}).get("name", "N/A")
        tls_cipher_suite = tls_server_hello.get("cipher_suite", {}).get("name", "N/A")
        tls_heartbeat = tls_server_hello.get("heartbeat", "N/A")
        
        cert_info = data.get("data", {}).get(service, {}).get("result", {}).get("tls", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("parsed", {})
        version = cert_info.get("version", "N/A")
        serial_number = cert_info.get("serial_number", "N/A")
        signature_algorithm = cert_info.get("signature_algorithm", {}).get("name", "N/A")
        issuer_dn = cert_info.get("issuer_dn", "N/A")
        subject_dn = cert_info.get("subject_dn", "N/A")
        
        validity = cert_info.get("validity", {})
        not_before = validity.get("start", "N/A")
        not_after = validity.get("end", "N/A")
        
        key_alg = cert_info.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "N/A")
        subject_key_output = []
        if key_alg == "RSA":
            rsa_key_info = cert_info.get("subject_key_info", {}).get("rsa_public_key", {})
            public_key_size = rsa_key_info.get("length", "N/A")
            modulus = rsa_key_info.get("modulus", "N/A")
            exponent = rsa_key_info.get("exponent", "N/A")
            subject_key_output.append(f"Public Key Algorithm: {key_alg}")
            subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
            subject_key_output.append(f"  modulus: {modulus}")
            subject_key_output.append(f"  exponent: {exponent}")
        elif key_alg == "ECDSA":
            ecdsa_key_info = cert_info.get("subject_key_info", {}).get("ecdsa_public_key", {})
            public_key_size = ecdsa_key_info.get("length", "N/A")
            pub = ecdsa_key_info.get("pub", "N/A")
            curve =  ecdsa_key_info.get("curve", "N/A")
            subject_key_output.append(f"Public Key Algorithm: {key_alg}")
            subject_key_output.append(f"Public-Key: ({public_key_size} bit)")
            subject_key_output.append(f"  pub: {pub}")
            subject_key_output.append(f"  curve: {curve}")

        signature = cert_info.get('signature', {})
        SSL_banner = (
            """\
            Version: {tls_version}
            CipherSuit: {tls_cipher_suite}
            HeartBeat: {tls_heartbeat}
        Certificate Information:
            Version: {version}
            Serial Number: {serial_number}
            Signature Algorithm: {signature_algorithm}
            Issuer: {issuer_dn}
            Validity:
                Not Before: {not_before}
                Not After : {not_after}
            Subject: {subject_dn}
                {subject_key_output}
            Signature Algorithm: {signature_algorithm_name}
            Signature Value: {signature_value}
            Signature Self Signed: {signature_self_signed}\
        """
        ).format(
            tls_version=tls_version,
            tls_cipher_suite=tls_cipher_suite,
            tls_heartbeat=tls_heartbeat,
            version=version,
            serial_number=serial_number,
            signature_algorithm=signature_algorithm,
            issuer_dn=issuer_dn,
            not_before=not_before,
            not_after=not_after,
            subject_dn=subject_dn,
            subject_key_output='\n\t'.join(subject_key_output),
            signature_algorithm_name=signature.get('signature_algorithm', {}).get('name', 'N/A'),
            signature_value=signature.get('value', 'N/A'),
            signature_self_signed=signature.get('self_signed', 'N/A')
        )

    banner = (
        "Supported Versions: {supported_versions}\n"
        "Protocol Error:\n    {protocol_error}\n"
        "Startup Error:\n    {startup_error}\n"
        "SSL Certificate:\n    {SSL_banner}"
    ).format(
        supported_versions=supported_versions,
        protocol_error=format_dict(protocol_error),
        startup_error=format_dict(startup_error),
        SSL_banner=SSL_banner
    )
    ip = data.get('ip', 'N/A')
    return ip, banner

def extract_amqp091_data(service, data):
    result = data['data'].get(service, {}).get('result', {})
    server_properties = result.get('server_properties', {})

    unknown_props_str = server_properties.get('unknown_props', '{}')
    unknown_props = json.loads(unknown_props_str)
    capabilities = unknown_props.get('capabilities', {})

    banner = (
        f"Product: {server_properties.get('product', 'Unknown')}\n"
        f"Product Version: {server_properties.get('version', 'Unknown')}\n"
        f"Platform: {server_properties.get('platform', 'Unknown')}\n"
        f"Capabilities:\n"
    )

    for key, value in capabilities.items():
        banner += f"    {key.replace('_', ' ').capitalize()}: {value}\n"

    ip = data.get('ip', 'N/A')
    return ip, banner

def extract_redis_data(service, data):
    result = data.get('data', {}).get(service, {}).get('result', {})

    ping_response = result.get('ping_response', 'Unknown')
    info_response = result.get('info_response', 'Unknown')
    nonexistent_response = result.get('nonexistent_response', 'Unknown')
    quit_response = result.get('quit_response', 'Unknown')

    banner = (
        f"Ping Response: {ping_response}\n"
        f"Info Response:\n{info_response}\n"
        f"Nonexistent Response: {nonexistent_response}\n"
        f"Quit Response: {quit_response}"
    )
    ip = data.get('ip', 'N/A')
    return ip, banner

def extract_mongodb_data(service, data):
    result = data.get('data', {}).get(service, {}).get('result', {})

    is_master = result.get('is_master', {})
    build_info = result.get('build_info', {})

    banner = (
        f"Primary Node:\n"
        f"    {format_dict(is_master)}\n"
        f"Build Info:\n"
        f"    {format_dict(build_info)}"
    )
    ip = data.get('ip', 'N/A')
    return ip, banner

def extract_zgrab_data(zgrab_results, gps_results:list, port_dir:Path):
    with open(zgrab_results, 'r') as file:
        for line in file:
            data = json.loads(line)
            service = get_service(data)
            match service:
                case "banner":
                    ip, banner = extract_banner(service, data)
                case "ftp":
                    ip, banner = extract_banner(service, data)
                case "ssh":
                    ip, banner = extract_ssh_data(service, data)
                case "telnet":
                    ip, banner = extract_banner(service, data)
                case "smtp" | "smtp(ftp-smtp)" | "smtp(smtp-ftp)" | "smtp(imap-smtp-ftp)" | "smtp(smtp-ftp-imap)" | "smtp(smtp-pop3)":
                    ip, banner = extract_banner(service, data)
                case "http":
                    ip, banner = extract_http_data(service, data)
                case "imap" | "imap(pop3-imap)" | "imap(imap-pop3)":
                    ip, banner = extract_banner(service, data)
                case "pop3":
                    ip, banner = extract_banner(service, data)
                case "tls":
                    ip, banner = extract_tls_data(service, data)
                case "mysql" | "mssql":
                    ip, banner = extract_sql_data(service, data)
                case "smb":
                    ip, banner = extract_smb_data(service, data)
                case "oracle":
                    ip, banner = extract_oracle_data(service, data)
                case "postgres":
                    ip, banner = extract_postgres_data(service, data)
                case "amqp091":
                    ip, banner = extract_amqp091_data(service, data)
                case "redis":
                    ip, banner = extract_redis_data(service, data)
                case "mongodb":
                    ip, banner = extract_mongodb_data(service, data)
                case _:  
                    print(f"no specific case for {service}")
                    continue
            
            asn, _ = query(ip)
            if asn is None:
                asn = ""
            GPS_json_data = {
                            "ip": ip, 
                            "p": port_dir.name, 
                            "asn": asn, 
                            "data": banner, 
                            "fingerprint": service, 
                            "w": "1"
                        }
            gps_results.append(json.dumps(GPS_json_data))

if __name__ == '__main__':

    file_name = 'zgrab-result'
    outfile = open('gps-prior-res', "w")
    gps_results = []
    with open(file_name, 'r') as file:
        for line in file:
            data = json.loads(line)
            service = get_service(data)
            match service:
                case "ftp":
                    ip, banner = extract_banner(service, data)
                case "ssh":
                    ip, banner = extract_ssh_data(service, data)
                case "telnet":
                    ip, banner = extract_banner(service, data)
                case "smtp" | "smtp(ftp-smtp)" | "smtp(smtp-ftp)" | "smtp(imap-smtp-ftp)" | "smtp(smtp-ftp-imap)" | "smtp(smtp-pop3)":
                    ip, banner = extract_banner(service, data)
                case "http":
                    ip, banner = extract_http_data(service, data)
                case "imap" | "imap(pop3-imap)" | "imap(imap-pop3)":
                    ip, banner = extract_banner(service, data)
                case "pop3":
                    ip, banner = extract_banner(service, data)
                case "tls":
                    ip, banner = extract_tls_data(service, data)
                case "mysql" | "mssql":
                    ip, banner = extract_sql_data(service, data)
                case "smb":
                    ip, banner = extract_smb_data(service, data)
                case "oracle":
                    ip, banner = extract_oracle_data(service, data)
                case "postgres":
                    ip, banner = extract_postgres_data(service, data)
                case "amqp091":
                    ip, banner = extract_amqp091_data(service, data)
                case "redis":
                    ip, banner = extract_redis_data(service, data)
                case "mongodb":
                    ip, banner = extract_mongodb_data(service, data)
                case _:  
                    print(f"no specific case for {service}")
                    continue
            
            GPS_json_data = {
                            "ip": ip, 
                            "p": "", 
                            "asn": "", 
                            "data": banner, 
                            "fingerprint": service, 
                            "w": ""
                        }
            gps_results.append(json.dumps(GPS_json_data))
            if len(gps_results) >= 10000:
                            outfile.write('\n'.join(gps_results) + '\n')
                            gps_results = []

        if gps_results:
            outfile.write('\n'.join(gps_results) + '\n')

        outfile.close()