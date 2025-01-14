# funciones/pais.py

import geoip2.database
import ipaddress
import os

# Function to get country name from IP using GeoIP2
def get_country(ip, reader):
    try:
        # geoip2 expects a string IP address
        response = reader.country(ip)
        return response.country.name
    except geoip2.errors.AddressNotFoundError:
        return "Unknown"
    except ValueError:
        return "Invalid IP"
    except Exception as e:
        return f"Error: {e}"

def block_ips_htaccess(blacklisted_ips, htaccess_path):
    """
    Adds the blocked IPs to the .htaccess file within specific markers using Apache 2.4+ syntax.
    Only adds new IPs that are not already present to prevent duplication.
    """
    # Define markers to identify the block section
    start_marker = "# BEGIN Blocked IPs by Country"
    end_marker = "# END Blocked IPs by Country"

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
        print("No new IPs to add to the country-based block.")
        return

    # Prepare the block rules to add
    block_rules = []
    if block_start_index is not None and block_end_index is not None:
        # Insert new IPs before the end marker
        for ip in new_ips:
            block_rules.append(f"    Require not ip {ip}\n")
        # Insert the new rules into the existing block
        new_lines = lines[:block_end_index] + block_rules + lines[block_end_index:]
        print(f"Adding {len(new_ips)} new IPs to the existing country-based blocked IPs section.")
    else:
        # If block section doesn't exist, create it
        block_rules = [start_marker + "\n", "<RequireAll>\n", "    Require all granted\n"]
        for ip in new_ips:
            block_rules.append(f"    Require not ip {ip}\n")
        block_rules.append("</RequireAll>\n")
        block_rules.append(end_marker + "\n")
        new_lines = lines + ["\n"] + block_rules
        print(f"Creating a new country-based blocked IPs section with {len(new_ips)} IPs.")

    # Write the updated .htaccess content
    try:
        with open(htaccess_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Successfully updated {htaccess_path} with new blocked IPs by country.")
    except Exception as e:
        print(f"Error writing to {htaccess_path}: {e}")

def main():
    # Path to the Apache log file
    log_file_path = "/var/log/apache2/jocarsa-oldlace-access.log"
    
    # Path to the GeoLite2 Country MMDB database
    mmdb_path = 'GeoLite2-Country.mmdb'  # Update this path if necessary
    
    # Define the list of non-desired (blacklisted) countries
    non_desired_countries = [
        "China",
        "Ukraine",
        "Singapore"
    ]
    
    # Path to the .htaccess file
    htaccess_path = "/var/www/html/jocarsa-oldlace/.htaccess"
    
    # Backup the existing .htaccess file
    try:
        if os.path.exists(htaccess_path):
            backup_path = htaccess_path + ".backup_country"
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

    # Count occurrences of each IP
    diccionario_ips = {}
    for linea in lineas:
        try:
            # Assuming the IP is the first part before a "-"
            ip = linea.split("-")[0].strip()
            # Validate IP format
            ipaddress.IPv4Address(ip)
            if ip not in diccionario_ips:
                diccionario_ips[ip] = 1
            else:
                diccionario_ips[ip] += 1
        except ipaddress.AddressValueError:
            # Skip lines with invalid IP addresses
            continue

    # Initialize GeoIP2 reader
    try:
        reader = geoip2.database.Reader(mmdb_path)
    except FileNotFoundError:
        print(f"Error: The GeoLite2 database file {mmdb_path} does not exist.")
        return
    except Exception as e:
        print(f"An error occurred while opening the GeoLite2 database: {e}")
        return

    # Dictionaries to hold country counts and blacklisted IPs
    diccionario_paises = {}
    unknown_ips = []
    blacklisted_ips = {}

    # Iterate over each IP and map to country
    for ip, count in diccionario_ips.items():
        country = get_country(ip, reader)
        if country not in ["Unknown", "Invalid IP", "Error"]:
            if country in non_desired_countries:
                # Add to blacklisted IPs
                blacklisted_ips[ip] = count
            else:
                # Count normally for desired countries
                if country not in diccionario_paises:
                    diccionario_paises[country] = count
                else:
                    diccionario_paises[country] += count
        else:
            unknown_ips.append(ip)

    # Close the GeoIP2 reader
    reader.close()

    # Sort the countries by count in descending order
    ordenado_paises = dict(
        sorted(
            diccionario_paises.items(),
            key=lambda item: item[1],
            reverse=True
        )
    )

    # Sort the blacklisted IPs by count in descending order
    ordenado_blacklisted = dict(
        sorted(
            blacklisted_ips.items(),
            key=lambda item: item[1],
            reverse=True
        )
    )

    # Print the sorted dictionary of desired countries
    print("Desired Countries:")
    for country, count in ordenado_paises.items():
        print(f"{country}: {count}")

    # Print the sorted dictionary of blacklisted countries' IPs
    print("\nBlacklisted Countries:")
    for ip, count in ordenado_blacklisted.items():
        print(f"{ip}: {count}")

    # Optional: Print summary of unknowns
    print(f"\nUnknown/Invalid: {len(unknown_ips)}")

    # Optionally, log unknown IPs to a file for further analysis
    try:
        with open('unknown_ips_country.log', 'w') as f:
            for ip in unknown_ips:
                f.write(f"{ip}\n")
        print("Unknown IPs logged to unknown_ips_country.log")
    except Exception as e:
        print(f"Error writing unknown IPs to file: {e}")

    # Optionally, log blacklisted IPs to a separate file
    try:
        with open('blacklisted_ips_country.log', 'w') as f:
            for ip, count in ordenado_blacklisted.items():
                f.write(f"{ip} - Count: {count}\n")
        print("Blacklisted IPs by country logged to blacklisted_ips_country.log")
    except Exception as e:
        print(f"Error writing blacklisted IPs to file: {e}")

    # Block the blacklisted IPs by updating the .htaccess file
    if ordenado_blacklisted:
        block_ips_htaccess(ordenado_blacklisted.keys(), htaccess_path)
    else:
        print("No blacklisted IPs by country to block.")
