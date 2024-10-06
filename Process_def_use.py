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

# filename = 'readelf_def_use_text.txt'  
# tbfilename = 'tb_readelf_text.txt'
# generate the def-use pairs from the input text
# def process_blocks(input_text):
#     # Initialize lists to keep track of def-use pairs and all uses
#     def_use_pairs = []
#     all_uses = []

#     # Variables to track the current definition and its uses
#     current_def = None
#     uses_for_current_def = []
#     with open(filename, 'r') as file:
#         input_text = file.read()
#     # Process each line in the input text

#     for line in input_text.split('\n'):
#         def_match = re.search(r"def: (?:<(0x[0-9a-f]+)|\[External \[\]\])", line)
#         uses_match = re.search(r"uses: \{([^}]+)\}", line)

#         if def_match:
#             # If there's a current definition with uses, store them before moving on
#             if current_def is not None and uses_for_current_def:
#                 # Add non-duplicate def-use pairs
#                 for use in uses_for_current_def:
#                     if current_def != use:  
#                         def_use_pairs.append((current_def, use))
#                 uses_for_current_def = []

#             current_def = def_match.group(1) if def_match.group(1) else '0'

#         if uses_match:
#             # Extract uses and extend the global list of uses
#             current_uses = re.findall(r"<(0x[0-9a-f]+)", uses_match.group(1))
#             all_uses.extend(current_uses)

#             # If there's a current definition, add these uses to it
#             if current_def:
#                 uses_for_current_def.extend(current_uses)

#     # Handle any remaining uses for the last definition
#     if current_def and uses_for_current_def:
#         for use in uses_for_current_def:
#             if current_def != use:  # Again, check if def and use are different
#                 def_use_pairs.append((current_def, use))

#     # Deduplicate pairs and sort them
#     def_use_pairs = sorted(set(def_use_pairs), key=lambda x: (x[0], x[1]))

#     # Optionally, print the def-use pairs
#     for pair in def_use_pairs:
#         print(f"Def-Use Pair: {pair}")

#     return def_use_pairs


##test for the removing the duplicates change time: 16.06
# import re

# def process_blocks(input_text):
#     # Initialize lists to keep track of def-use pairs and all uses
#     def_use_pairs = []
#     all_uses = []

#     # Variables to track the current definition and its uses
#     current_def = None
#     uses_for_current_def = []
#     with open(filename, 'r') as file:
#         input_text = file.read()
#     # Process each line in the input text
#     # Process each line in the input text
#     for line in input_text.split('\n'):
#         def_match = re.search(r"def: (?:<(0x[0-9a-f]+)|\[External \[\]\])", line)
#         uses_match = re.search(r"uses: \{([^}]+)\}", line)

#         if def_match:
#             # If there's a current definition with uses, store them before moving on
#             if current_def is not None and uses_for_current_def:
#                 # Add non-duplicate def-use pairs
#                 for use in uses_for_current_def:
#                     if current_def != use:  # Check if def and use are different
#                         def_use_pairs.append((current_def, use))
#                 uses_for_current_def = []

#             # Update the current definition only if it's not [External []]
#             if def_match.group(1):
#                 current_def = def_match.group(1)
#             else:
#                 # Skip adding uses for [External []] definitions
#                 current_def = None

#         if uses_match and current_def:
#             # Extract uses and extend the global list of uses
#             current_uses = re.findall(r"<(0x[0-9a-f]+)", uses_match.group(1))
#             all_uses.extend(current_uses)

#             # Add these uses to the current definition, if valid
#             uses_for_current_def.extend(current_uses)

#     # Handle any remaining uses for the last definition
#     if current_def and uses_for_current_def:
#         for use in uses_for_current_def:
#             if current_def != use:  # Again, check if def and use are different
#                 def_use_pairs.append((current_def, use))

#     # Deduplicate pairs and sort them
#     def_use_pairs = sorted(set(def_use_pairs), key=lambda x: (x[0], x[1]))

#     # Optionally, print the def-use pairs
#     for pair in def_use_pairs:
#         print(f"Def-Use Pair: {pair}")

#     return def_use_pairs


import re
#-----------------------------------------------all situations are handled-----------------------------------------
# Helper function to parse hex address correctly
# def parse_hex_address(text):
#     match = re.search(r"0x[0-9a-f]+", text)
#     if match:
#         return match.group(0)
#     return None

# # Parsing function blocks
# def parse_function_blocks(input_text):
#     r = re.compile(r'^Function .*?(?=^Function|\Z)', re.M | re.DOTALL)
#     return r.findall(input_text)

# # Parsing definitions and uses within a block
# def parse_definitions_uses(block):
#     defs_uses = []
#     lines = block.split('\n')
#     current_def = None

#     for line in lines:
#         def_match = re.search(r'def: (?:<([^>]+)>|\[External \[\]\])', line)
#         uses_match = re.search(r'uses: (?:{([^}]+)}|set\(\))', line)
        
#         if def_match:
#             if def_match.group(1):
#                 current_def = parse_hex_address(def_match.group(1))
#             else:
#                 current_def = "0"  # Marking external defs as '0x0' for distinction
                
#         if uses_match:
#             if uses_match.group(1):
#                 uses = re.findall(r'<([^>]+)>', uses_match.group(1))
#                 for use in uses:
#                     use_addr = parse_hex_address(use)
#                     if current_def and use_addr and current_def != use_addr:  # Check if def and use are different
#                         defs_uses.append((current_def, use_addr))

#     return defs_uses

# # Parsing functions to extract names and addresses
# def parse_functions(text):
#     pattern = r"Function\s+(\w+)\s+\((0x[0-9a-f]+)\)"
#     return [(m[0], int(m[1], 16)) for m in re.findall(pattern, text)]

# # Check if address is outside function range
# def is_outside_function_range(addr, func_start, func_end):
#     if addr is None or addr == "0":  # Do not consider None or '0x0' as an outside range
#         return False
#     address = int(addr, 16)
#     return address < func_start or address >= func_end

# # Main function to parse and check definitions and uses
# def find_outside_definitions_uses(input_text):
#     with open(filename, 'r') as file:
#         input_text = file.read()
# #     
#     function_blocks = parse_function_blocks(input_text)
#     functions = parse_functions(input_text)
#     outside_defs_uses = []

#     for block, func in zip(function_blocks, functions):
#         defs_uses = parse_definitions_uses(block)
#         func_start = func[1]
#         func_end = functions[functions.index(func) + 1][1] if functions.index(func) < len(functions) - 1 else 0xFFFFFFFF
        
#         for d, u in defs_uses:
#             if is_outside_function_range(d, func_start, func_end) or is_outside_function_range(u, func_start, func_end):
#                 outside_defs_uses.append((d, u))

#     return outside_defs_uses
#----------------------------------------------
#only consider the external situation and without function range
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




# def assign_def_use_to_blocks(def_use_pairs, tb_data):
#     for block in tb_data:
#         block['num_def'] = 0
#         block['num_use'] = 0
#         block['def_use_chain'] = []

#     for info in data:
#         # for def_addr in info[0]:
#             # for block in tb_data:
#                 # pc_start = block['pc']
#                 # pc_end = hex(int(pc_start, 16) + int(block['size'], 16))
#                 # print (f"Block {pc_start} - {pc_end}:")
#                 # print(def_addr)
#                 # if (info[0] >= pc_start and info[0] <= pc_end):
#                 #     block['num_def'] += 1
#                 #     block['def_use_chain'].append(info)
                
#     # for use_addr in info[1]:
#         for block in tb_data:
#             pc_start = block['pc']
#             pc_end = hex(int(pc_start, 16) + int(block['size'], 16))
#             # print (f"Block {pc_start} - {pc_end}:")
#             # print(use_addr)
#             if info[1] >= pc_start and info[1] <= pc_end:
#                 # print(f"Block {pc_start} - {pc_end}:")
#                 # print(use_addr)
#                 block['num_use'] += 1
#                 block['def_use_chain'].append(info)
                    
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
        # for def_addr in info[0]:
            # for block in tb_data:
                # pc_start = block['pc']
                # pc_end = hex(int(pc_start, 16) + int(block['size'], 16))
                # print (f"Block {pc_start} - {pc_end}:")
                # print(def_addr)
                # if (info[0] >= pc_start and info[0] <= pc_end):
                #     block['num_def'] += 1
                #     block['def_use_chain'].append(info)
                
        # for use_addr in info[1]:
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




