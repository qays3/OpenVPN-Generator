# For Root Use

import os
import subprocess
import time

def run_command(command, sudo=False, background=False):
    
    if sudo:
        command = f"sudo {command}"
    
    try:
        start_time = time.time()
        if background:
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"Running command '{command}' in the background...")
            return result
        else:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            elapsed_time = time.time() - start_time
            if result.returncode != 0:
                raise Exception(f"Error running command: {command}\n{result.stderr}")
            print(f"Command '{command}' completed in {elapsed_time:.2f}s")
            return result.stdout.strip()
    except Exception as e:
        print(f"Error in command execution: {e}")
        return None


def install_dependencies():
    
    print("Installing dependencies...")
    result = run_command("apt update && apt install -y openvpn easy-rsa bridge-utils curl", sudo=True)
    if result is None:
        print("Failed to install dependencies.")
    else:
        print("Dependencies installed successfully.")


def fix_repository_issues():
    
    print("Fixing repository issues...")

    try:
        
        run_command("rm -f /etc/apt/sources.list.d/influxdata.list", sudo=True)
        run_command("rm -f /etc/apt/sources.list.d/influxdb.list", sudo=True)

        
        influxdb_key = "/usr/share/keyrings/influxdb-archive-keyring.gpg"
        if not os.path.exists(influxdb_key):
            run_command("curl -fsSL https://repos.influxdata.com/influxdb.key | gpg --dearmor -o /usr/share/keyrings/influxdb-archive-keyring.gpg", sudo=True)
            run_command("echo 'deb [signed-by=/usr/share/keyrings/influxdb-archive-keyring.gpg] https://repos.influxdata.com/debian buster stable' | sudo tee /etc/apt/sources.list.d/influxdata.list", sudo=True)

        
        run_command("rm -f /etc/apt/sources.list.d/docker.list", sudo=True)

        
        docker_key = "/usr/share/keyrings/docker-archive-keyring.gpg"
        if not os.path.exists(docker_key):
            run_command("curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg", sudo=True)
            run_command("echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian bookworm stable' | sudo tee /etc/apt/sources.list.d/docker.list", sudo=True)

        
        run_command("apt update", sudo=True)
        print("Repository issues fixed.")
    except Exception as e:
        print(f"Error fixing repository issues: {e}")


def setup_easy_rsa():
    
    print("Setting up Easy-RSA...")

    easy_rsa_path = os.path.expanduser("~/easy-rsa")
    
    try:
        
        if not os.path.exists(easy_rsa_path):
            print("Creating new Easy-RSA directory...")
            run_command(f"mkdir -p {easy_rsa_path}", sudo=False)
        else:
            print(f"Easy-RSA directory already exists at {easy_rsa_path}")

        
        if not os.path.exists(os.path.join(easy_rsa_path, "easyrsa")):
            print("Copying Easy-RSA files to the new directory...")
            run_command(f"cp -r /usr/share/easy-rsa/* {easy_rsa_path}", sudo=False)
        else:
            print("Easy-RSA files already exist in the directory.")

        os.chdir(easy_rsa_path)

        
        if not os.path.exists(os.path.join(easy_rsa_path, "pki")):
            print("Initializing PKI...")
            result = run_command("./easyrsa init-pki", sudo=False)
            print(f"Result of initializing PKI: {result}")
        else:
            print("PKI already initialized.")

        
        if not os.path.exists(os.path.join(easy_rsa_path, "pki", "ca.crt")):
            print("Building Certificate Authority (CA)...")
            result = run_command("echo -ne '\\n' | ./easyrsa build-ca nopass", sudo=False)
            print(f"Result of building CA: {result}")
        else:
            print("CA already exists.")

        
        print("Generating server request using OpenSSL...")
        server_key_path = os.path.join(easy_rsa_path, "pki", "private", "server.key")
        server_csr_path = os.path.join(easy_rsa_path, "pki", "reqs", "server.csr")
        server_cert_path = os.path.join(easy_rsa_path, "pki", "issued", "server.crt")

        
        run_command(f"openssl genpkey -algorithm RSA -out {server_key_path} -aes256", sudo=False)

        
        run_command(f"openssl req -new -key {server_key_path} -out {server_csr_path} -subj \"/C=US/ST=State/L=City/O=Organization/CN=server\"", sudo=False)

        
        run_command(f"openssl x509 -req -in {server_csr_path} -CA {os.path.join(easy_rsa_path, 'pki', 'ca.crt')} -CAkey {os.path.join(easy_rsa_path, 'pki', 'private', 'ca.key')} -CAcreateserial -out {server_cert_path} -days 365", sudo=False)

        print("Server certificate generated successfully.")

        
        dh_param_path = os.path.join(easy_rsa_path, "pki", "dh.pem")
        if not os.path.exists(dh_param_path):
            print("Generating Diffie-Hellman parameters...")
            run_command(f"./easyrsa gen-dh", sudo=False)
        else:
            print("DH parameters already exist.")

        
        print("Generating client certificate using OpenSSL...")
        client_key_path = os.path.join(easy_rsa_path, "pki", "private", "client.key")
        client_csr_path = os.path.join(easy_rsa_path, "pki", "reqs", "client.csr")
        client_cert_path = os.path.join(easy_rsa_path, "pki", "issued", "client.crt")

        
        run_command(f"openssl genpkey -algorithm RSA -out {client_key_path} -aes256", sudo=False)

        
        run_command(f"openssl req -new -key {client_key_path} -out {client_csr_path} -subj \"/C=US/ST=State/L=City/O=Organization/CN=client\"", sudo=False)

        
        run_command(f"openssl x509 -req -in {client_csr_path} -CA {os.path.join(easy_rsa_path, 'pki', 'ca.crt')} -CAkey {os.path.join(easy_rsa_path, 'pki', 'private', 'ca.key')} -CAcreateserial -out {client_cert_path} -days 365", sudo=False)

        print("Client certificate generated successfully.")

        print("Easy-RSA setup complete.")
    except Exception as e:
        print(f"Error setting up Easy-RSA: {e}")


def generate_ovpn_file():
    
    print("Generating .ovpn client file...")

    client_ovpn_file = "/root/client.ovpn"
    
    
    ca_cert_path = "/root/easy-rsa/pki/ca.crt"
    client_cert_path = "/root/easy-rsa/pki/issued/client.crt"
    client_key_path = "/root/easy-rsa/pki/private/client.key"

    # Fetch the server IP dynamically using 'hostname -I'
    server_ip = run_command("hostname -I | awk '{print $1}'").strip()

    ovpn_content = f"""
client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca {ca_cert_path}
cert {client_cert_path}
key {client_key_path}
comp-lzo
verb 3
"""
    
    
    with open(client_ovpn_file, "w") as f:
        f.write(ovpn_content)

    print(f".ovpn client configuration file generated at {client_ovpn_file}")


def configure_openvpn_server():
    
    print("Configuring OpenVPN server...")
    try:
        run_command("mkdir -p /etc/openvpn/server", sudo=True)
        
        
        run_command("sudo cp /root/easy-rsa/pki/ca.crt /etc/openvpn/server/", sudo=True)
        run_command("sudo cp /root/easy-rsa/pki/issued/server.crt /etc/openvpn/server/", sudo=True)
        run_command("sudo cp /root/easy-rsa/pki/private/server.key /etc/openvpn/server/", sudo=True)
        run_command("sudo cp /root/easy-rsa/pki/dh.pem /etc/openvpn/server/", sudo=True)

        server_conf = """
        port 1194
        proto udp
        dev tun
        ca ca.crt
        cert server.crt
        key server.key
        dh dh.pem
        server 10.8.0.0 255.255.255.0
        push "redirect-gateway def1 bypass-dhcp"
        push "dhcp-option DNS 8.8.8.8"
        push "dhcp-option DNS 8.8.4.4"
        keepalive 10 120
        cipher AES-256-CBC
        auth SHA256
        comp-lzo
        user nobody
        group nogroup
        persist-key
        persist-tun
        status openvpn-status.log
        verb 3
        """
        with open("/etc/openvpn/server.conf", "w") as f:
            f.write(server_conf)

        print("OpenVPN server configured successfully.")
    except Exception as e:
        print(f"Error configuring OpenVPN server: {e}")


if __name__ == "__main__":
    install_dependencies()
    fix_repository_issues()
    setup_easy_rsa()
    configure_openvpn_server()
    generate_ovpn_file()