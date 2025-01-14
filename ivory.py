# main.py

from funciones.pais import main as country_block_main
from funciones.user_agent_block import main as user_agent_block_main

def main():
    print("Starting Country-Based IP Blocking...")
    country_block_main()
    
    print("\nStarting User-Agent-Based IP Blocking...")
    user_agent_block_main()
    
    print("\nIP Blocking Process Completed.")

if __name__ == "__main__":
    main()
