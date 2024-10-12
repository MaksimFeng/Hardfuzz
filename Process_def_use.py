import json
import re
from collections import OrderedDict
import sys

import re
#TO DO: change the def use pair
# Ensure there are enough arguments
if len(sys.argv) < 3:
    print("Usage: script.py <filename> <tbfilename>")
    sys.exit(1)

filename = sys.argv[1]
tbfilename = sys.argv[2]
output_json_filename = filename.split('.')[0] + 'newnewnewpc_def_use_chain.json'




import re

def parse_hex_address(text):
    match = re.search(r"0x[0-9a-f]+", text)
    if match:
        return match.group(0)
    return None

# Parsing function blocks
def parse_function_blocks(input_text):
    r = re.compile(r'^Function .*?(?=^Function|\Z)', re.M | re.DOTALL)
    return r.findall(input_text)

# Parsing definitions and uses within a block
def parse_definitions_uses(block):
    defs_uses = []
    lines = block.split('\n')
    current_def = None

    for line in lines:
        def_match = re.search(r'def: (?:<([^>]+)>|\[External \[\]\])', line)
        uses_match = re.search(r'uses: (?:{([^}]+)}|set\(\))', line)
        
        if def_match:
            if def_match.group(1):
                current_def = None  # Ignore non-external defs
            else:
                current_def = "0"  # Marking external defs as '0x0'
                
        if uses_match and current_def == "0":  # Only consider uses when the def is external
            if uses_match.group(1):
                uses = re.findall(r'<([^>]+)>', uses_match.group(1))
                for use in uses:
                    use_addr = parse_hex_address(use)
                    if use_addr:
                        defs_uses.append(("0", use_addr))

    return defs_uses

# Parsing functions to extract names and addresses
def parse_functions(text):
    pattern = r"Function\s+(\w+)\s+\((0x[0-9a-f]+)\)"
    return [(m[0], int(m[1], 16)) for m in re.findall(pattern, text)]

# Check if address is outside function range
def is_outside_function_range(addr, func_start, func_end):
    if addr is None or addr == "0":  # Do not consider None or '0x0' as an outside range
        return False
    address = int(addr, 16)
    return address < func_start or address >= func_end

# Main function to parse and check definitions and uses
def find_outside_definitions_uses(input_text):
    with open(filename, 'r') as file:
        input_text = file.read()
    function_blocks = parse_function_blocks(input_text)
    functions = parse_functions(input_text)
    outside_defs_uses = set()  # Use a set to store unique def-use pairs

    for block, func in zip(function_blocks, functions):
        defs_uses = parse_definitions_uses(block)
        func_start = func[1]
        func_end = functions[functions.index(func) + 1][1] if functions.index(func) < len(functions) - 1 else 0xFFFFFFFF
        
        for d, u in defs_uses:
            if is_outside_function_range(u, func_start, func_end):
                outside_defs_uses.add((d, u))  # Add def-use pair to the set

    return list(outside_defs_uses)  # Convert the set to a list before returning



def process_tb(filename):
    blocks = []

    with open(filename, 'r') as file:
        data = file.readlines()

    for i, line in enumerate(data):
        parts = line.split(', ')
        tb = parts[0].split(':')[1].strip()
        pc = parts[1].split(':')[1].strip()
        tb_code = parts[2].split(':')[1].strip()
        # Calculate strip for each block except the last one
        if i < len(data) - 1:
            next_tb = data[i + 1].split(', ')[2].split(':')[1].strip()
            next_pc = data[i + 1].split(', ')[1].split(':')[1].strip()
            size = hex(int(next_tb, 16) - int(tb_code, 16))
        else:  # Assign a default strip for the last block
            size = "0x200"  
        blocks.append({'tb': tb, 'pc': pc, 'tb_code': tb_code, 'size': size, "next_pc": next_pc})

    # Sort the blocks based on pc values
    sorted_blocks = sorted(blocks, key=lambda x: int(x['tb_code'], 16))

    return sorted_blocks

# Specify the path to the uploaded file

# Call the function with the updated filename
sorted_blocks = process_tb(tbfilename)



duplicate_data = find_outside_definitions_uses(filename)
data = list(set(duplicate_data))
# print(data)

tb_data = process_tb(tbfilename)
print(">>>>>>>>>>>>>>>>>>>>")

for block in tb_data:
        block['num_def'] = 0
        block['num_use'] = 0
        block['def_use_chain'] = []

for info in data:
        
            for block in tb_data:
                pc_start = block['pc']
                pc_end = hex(int(pc_start, 16) + int(block['size'], 16))
                # print (f"Block {pc_start} - {pc_end}:")
                # print(use_addr)
                # if info[1] >= pc_start and info[1] <= pc_end and info[1]<=block['next_pc']:
                if int(info[1], 16) >= int(pc_start, 16) and int(info[1], 16) <= int(pc_end, 16) and int(info[1], 16) <= int(block['next_pc'], 16):

                    # print(f"Block {pc_start} - {pc_end}:")
                    print(info[1])
                    block['num_use'] += 1
                    block['def_use_chain'].append(info)
# final_data = assign_def_use_to_blocks(data, tb_data)
for pop_data in tb_data:
    pop_data.pop('next_pc')



print(">>>>>>>>>>>>>>>>>>>>")
# print(tb_data)
with open(output_json_filename, 'w') as outfile:
    json.dump(tb_data, outfile)
print(">>>>>>>>>>>>>>>>>>>>")




