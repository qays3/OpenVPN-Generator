# For User Use

import os
import subprocess
import time
import random
import string

def run_command(command, sudo=False, background=False):
    if sudo:
        command = f"sudo {command}"
    try:
        start_time = time.time()
        if background:
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result
        else:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            elapsed_time = time.time() - start_time
            if result.returncode != 0:
                raise Exception(f"Error running command: {command}\n{result.stderr}")
            return result.stdout.strip()
    except Exception as e:
        return None

def setup_easy_rsa():
    easy_rsa_path = os.path.expanduser("~/easy-rsa")
    try:
        if not os.path.exists(easy_rsa_path):
            run_command(f"mkdir -p {easy_rsa_path}", sudo=False)
        if not os.path.exists(os.path.join(easy_rsa_path, "easyrsa")):
            run_command(f"cp -r /usr/share/easy-rsa/* {easy_rsa_path}", sudo=False)
        os.chdir(easy_rsa_path)

        if not os.path.exists(os.path.join(easy_rsa_path, "pki")):
            run_command("./easyrsa init-pki", sudo=False)
        if not os.path.exists(os.path.join(easy_rsa_path, "pki", "ca.crt")):
            run_command(f"echo -ne '\\n' | ./easyrsa build-ca nopass", sudo=False)
        
        server_key_path = os.path.join(easy_rsa_path, "pki", "private", "server.key")
        server_csr_path = os.path.join(easy_rsa_path, "pki", "reqs", "server.csr")
        server_cert_path = os.path.join(easy_rsa_path, "pki", "issued", "server.crt")
        run_command(f"openssl genpkey -algorithm RSA -out {server_key_path} -aes256 -pass pass:", sudo=False)  # No password
        run_command(f"openssl req -new -key {server_key_path} -out {server_csr_path} -subj \"/C=US/ST=State/L=City/O=Organization/CN=server\" -passin pass:", sudo=False)  # No password
        run_command(f"openssl x509 -req -in {server_csr_path} -CA {os.path.join(easy_rsa_path, 'pki', 'ca.crt')} -CAkey {os.path.join(easy_rsa_path, 'pki', 'private', 'ca.key')} -CAcreateserial -out {server_cert_path} -days 365 -passin pass:", sudo=False)  # No password

        dh_param_path = os.path.join(easy_rsa_path, "pki", "dh.pem")
        if not os.path.exists(dh_param_path):
            run_command(f"./easyrsa gen-dh", sudo=False)

        client_key_path = os.path.join(easy_rsa_path, "pki", "private", "client.key")
        client_csr_path = os.path.join(easy_rsa_path, "pki", "reqs", "client.csr")
        client_cert_path = os.path.join(easy_rsa_path, "pki", "issued", "client.crt")
        run_command(f"openssl genpkey -algorithm RSA -out {client_key_path} -aes256 -pass pass:", sudo=False)  # No password
        run_command(f"openssl req -new -key {client_key_path} -out {client_csr_path} -subj \"/C=US/ST=State/L=City/O=Organization/CN=client\" -passin pass:", sudo=False)  # No password
        run_command(f"openssl x509 -req -in {client_csr_path} -CA {os.path.join(easy_rsa_path, 'pki', 'ca.crt')} -CAkey {os.path.join(easy_rsa_path, 'pki', 'private', 'ca.key')} -CAcreateserial -out {client_cert_path} -days 365 -passin pass:", sudo=False)  # No password

    except Exception as e:
        print(f"Error setting up Easy-RSA: {e}")

def generate_ovpn_config():
    client_key_path = "/root/easy-rsa/pki/private/client.key"
    client_cert_path = "/root/easy-rsa/pki/issued/client.crt"
    ca_cert_path = "/root/easy-rsa/pki/ca.crt"
    
    with open(client_key_path, 'r') as key_file:
        client_key = key_file.read()

    with open(client_cert_path, 'r') as cert_file:
        client_cert = cert_file.read()

    with open(ca_cert_path, 'r') as ca_file:
        ca_cert = ca_file.read()

    server_ip = run_command("hostname -I | awk '{print $1}'", sudo=False)

    script_dir = os.path.dirname(os.path.realpath(__file__))
    ovpn_config_path = os.path.join(script_dir, "client.ovpn")

    ovpn_config = f"""
client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
<ca>
{ca_cert}
</ca>
<cert>
{client_cert}
</cert>
<key>
{client_key}
</key>
comp-lzo
verb 3
"""

    with open(ovpn_config_path, 'w') as ovpn_file:
        ovpn_file.write(ovpn_config)

def main():
    setup_easy_rsa()
    generate_ovpn_config()

if __name__ == "__main__":
    main()
