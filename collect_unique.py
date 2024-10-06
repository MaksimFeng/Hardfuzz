## usage: python test.py
## usage: python Process_def_use.py
# python collect_unique.py <path/to/json/file>
import json
import sys

if len(sys.argv) != 2:
    print("Usage: python collect_unique.py <path/to/json/file>")
    sys.exit(1)

filename = sys.argv[1]
output_json_filename = filename.split('.')[0] + 'newnewnewpc_def_use_chain.json'

# Specify the path to JSON file
# json_file_path = '/home/kai/project/fuzz/as_def_use_textnewnewpc_def_use_chain.json'

# Read the JSON data from the file
with open(filename, 'r') as file:
    data = json.load(file)

# Create a set to store unique elements across all "def_use_chain" arrays
unique_elements = set()

# Collect unique elements from all "def_use_chain" arrays
for item in data:
    unique_elements.update(map(tuple, item["def_use_chain"]))

# Update each "def_use_chain" array with only the unique elements
for item in data:
    item["def_use_chain"] = [list(element) for element in unique_elements if list(element) in item["def_use_chain"]]


# Save the modified data to a new JSON file
with open(output_json_filename, 'w') as file:
    json.dump(data, file, separators=(',', ':'))

print(f"Modified JSON data saved to: {output_json_filename}")