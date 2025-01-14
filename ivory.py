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
    """
    # Define markers to identify the block section
    start_marker = "# BEGIN Blocked IPs"
    end_marker = "# END Blocked IPs"

    # Prepare the block rules using <RequireAll>
    block_rules = [start_marker + "\n", "<RequireAll>\n", "    Require all granted\n"]
    for ip in blacklisted_ips:
        block_rules.append(f"    Require not ip {ip}\n")
    block_rules.append("</RequireAll>\n")
    block_rules.append(end_marker + "\n")

    # Read existing .htaccess content
    if os.path.exists(htaccess_path):
        with open(htaccess_path, 'r') as f:
            lines = f.readlines()
    else:
        lines = []

    # Check if the block section already exists
    try:
        start_index = lines.index(start_marker + "\n")
        end_index = lines.index(end_marker + "\n", start_index)
        # Replace the existing block section
        new_lines = lines[:start_index] + block_rules + lines[end_index + 1:]
        print(f"Existing blocked IPs section found. Updating with {len(blacklisted_ips)} IPs.")
    except ValueError:
        # If markers not found, append the block section
        new_lines = lines + ["\n"] + block_rules
        print(f"No existing blocked IPs section found. Adding a new section with {len(blacklisted_ips)} IPs.")

    # Write the updated .htaccess content
    try:
        with open(htaccess_path, 'w') as f:
            f.writelines(new_lines)
        print(f"Successfully updated {htaccess_path} with blocked IPs.")
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
            backup_path = htaccess_path + ".backup"
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
    # If you prefer to block based on frequency, otherwise you can block all
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
        with open('unknown_ips.log', 'w') as f:
            for ip in unknown_ips:
                f.write(f"{ip}\n")
        print("Unknown IPs logged to unknown_ips.log")
    except Exception as e:
        print(f"Error writing unknown IPs to file: {e}")

    # Optionally, log blacklisted IPs to a separate file
    try:
        with open('blacklisted_ips.log', 'w') as f:
            for ip, count in ordenado_blacklisted.items():
                f.write(f"{ip} - Count: {count}\n")
        print("Blacklisted IPs logged to blacklisted_ips.log")
    except Exception as e:
        print(f"Error writing blacklisted IPs to file: {e}")

    # Block the blacklisted IPs by updating the .htaccess file
    if ordenado_blacklisted:
        block_ips_htaccess(ordenado_blacklisted.keys(), htaccess_path)
    else:
        print("No blacklisted IPs to block.")

if __name__ == "__main__":
    main()
