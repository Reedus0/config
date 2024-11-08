import json

def output_to_file(data):
    with open("result.json", "w") as file: 
        file.write(json.dumps(data))