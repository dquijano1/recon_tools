import os
from modules import dns_lookup, port_scanning, whois_lookup

def results_printer():
    result_list=[]
    result_dir="results"
    if os.path.exists(result_dir):
        result_list= os.listdir(result_dir)
        if not result_list:
            print(f"No files inside {result_dir} directory")
        else:
            print(f"--- Files in directory {result_dir}/ ---")
            for file in result_list:
                print(f"- {file}")
    else:
        print(f"Directory {result_dir} does not exist")



def main():
    print("Welcome to Rcn Tool")
    print("Select a tool tool you want to use")
    print("1.- WHOIS lookup and DNS lookup")
    print("2.- Port Scanning")
    user_input=input("#").strip()

    

if __name__ == "__main__":
    main()
