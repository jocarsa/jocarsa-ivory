# funciones/user_agent_block.py

import ipaddress
import os

def block_ips_htaccess(blacklisted_ips, htaccess_path):
    """
    Adds the blocked IPs to the .htaccess file within specific markers using Apache 2.4+ syntax.
    Only adds new IPs that are not already present to prevent duplication.
    """
    # Define markers to identify the block section
    start_marker = "# BEGIN Blocked IPs by User Agent"
    end_marker = "# END Blocked IPs by User Agent"

    # Read existing .htaccess content
    if os.path.exists(htaccess_path):
        with open(htaccess_path, 'r') as f:
            lines = f.readlines()
    else:
        lines = []

    # Extract existing blocked IPs
    existing_ips = set()
    within_block = False
    block_start_index = None
    block_end_index = None

    for index, line in enumerate(lines):
        if line.strip() == start_marker:
            within_block = True
            block_start_index = index
            continue
        if line.strip() == end_marker:
            within_block = False
            block_end_index = index
            break
        if within_block:
            if line.strip().startswith("Require not ip"):
                ip = line.strip().split("Require not ip")[-1].strip()
                existing_ips.add(ip)

    # Determine new IPs to add
    new_ips = set(blacklisted_ips) - existing_ips
    if not new_ips:
        print("No new IPs to add to the user-agent-based block.")
        return

    # Prepare the block rules to add
    block_rules = []
    if block_start_index is not None and block_end_index is not None:
        # Insert new IPs before the end marker
        for ip in new_ips:
            block_rules.append(f"    Require not ip {ip}\n")
        # Insert the new rules into the existing block
        new_lines = lines[:block_end_index] + block_rules + lines[block_end_index:]
        print(f"Adding {len(new_ips)} new IPs to the existing user-agent-based blocked IPs section.")
    else:
        # If block section doesn't exist, create it
        block_rules = [start_marker + "\n", "<RequireAll>\n", "    Require all granted\n"]
        for ip in new_ips:
            block_rules.append(f"    Require not ip {ip}\n")
        block_rules.append("</RequireAll>\n")
        block_rules.append(end_marker + "\n")
        new_lines = lines + ["\n"] + block_rules
        print(f"Creating a new user-agent-based blocked IPs section with {len(new_ips)} IPs.")

    # Write the updated .htaccess content
    try:
        with open(htaccess_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Successfully updated {htaccess_path} with new blocked IPs by user agent.")
    except Exception as e:
        print(f"Error writing to {htaccess_path}: {e}")

def main():
    # Path to the Apache log file
    log_file_path = "/var/log/apache2/jocarsa-oldlace-access.log"
    
    # Path to the .htaccess file
    htaccess_path = "/var/www/html/jocarsa-oldlace/.htaccess"
    
    # Backup the existing .htaccess file
    try:
        if os.path.exists(htaccess_path):
            backup_path = htaccess_path + ".backup_user_agent"
            with open(htaccess_path, 'r') as original, open(backup_path, 'w') as backup:
                backup.write(original.read())
            print(f"Backup of .htaccess created at {backup_path}")
    except Exception as e:
        print(f"Error creating backup of .htaccess: {e}")
        return
    
    # Open and read the log file
    try:
        with open(log_file_path, 'r') as archivo:
            lineas = archivo.readlines()
    except FileNotFoundError:
        print(f"Error: The file {log_file_path} does not exist.")
        return
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return

    # Collect IPs with user agent "-"
    blacklisted_ips = set()
    for linea in lineas:
        try:
            # Assuming the log format is similar to combined log format:
            # IP - - [date] "request" status size "referer" "user-agent"
            parts = linea.split('"')
            if len(parts) >= 6:
                user_agent = parts[5].strip()
                if user_agent == "-":
                    ip = linea.split()[0]
                    # Validate IP format
                    ipaddress.IPv4Address(ip)
                    blacklisted_ips.add(ip)
        except ipaddress.AddressValueError:
            # Skip lines with invalid IP addresses
            continue
        except IndexError:
            # Skip lines that don't conform to expected format
            continue

    # Sort the blacklisted IPs (optional: by frequency or other criteria)
    # Here, we're just converting to a sorted list
    ordenado_blacklisted = sorted(blacklisted_ips)

    # Print the sorted list of blacklisted IPs
    print("Blacklisted IPs by User Agent:")
    for ip in ordenado_blacklisted:
        print(ip)

    # Optionally, log blacklisted IPs to a separate file
    try:
        with open('blacklisted_ips_user_agent.log', 'w') as f:
            for ip in ordenado_blacklisted:
                f.write(f"{ip}\n")
        print("Blacklisted IPs by user agent logged to blacklisted_ips_user_agent.log")
    except Exception as e:
        print(f"Error writing blacklisted IPs to file: {e}")

    # Block the blacklisted IPs by updating the .htaccess file
    if ordenado_blacklisted:
        block_ips_htaccess(ordenado_blacklisted, htaccess_path)
    else:
        print("No blacklisted IPs by user agent to block.")
