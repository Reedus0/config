import sys
from logger import *
from file import *
from regex import *
from output import *

def main():
    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} filename")
        exit(1)

    file = sys.argv[1]

    init_logging()
    
    log(f"Extracting from {file}...")

    result = {}

    result["filename"] = file
    
    result["server_ip"], result["server_port"] = find_ip_and_port(file)
    result["user_agent"] = find_user_agent(file)
    result["url"] = find_c2_url(file)
    result["content_type"] = find_content_type(file)

    output_to_file(result)

if __name__ == "__main__":
    main()