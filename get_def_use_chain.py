import angr
import sys
import struct
import networkx as nx
import monkeyhex
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
import os
import matplotlib.pyplot as plt
from networkx.drawing.nx_pydot import write_dot
binary2_path = '/home/kai/Arduino/programbuggynochange/build/arduino.sam.arduino_due_x_dbg/programbuggynochange.ino.elf'
proj = angr.Project(
    binary2_path,
 
    auto_load_libs=False
)
cfg2 = proj.analyses.CFGEmulated(    
    normalize=True,
    context_sensitivity_level=3,  # Increase context sensitivity if needed
    # starts=[entry_point],
    keep_state=True,
    enable_function_hints=True
    )

count = 0
for func_addr, func in cfg2.kb.functions.items():
    print(f"\nFunction at 0x{func_addr:x}:")
    # Each function contains a list of basic blocks
    # print the number of basic blocks in the function
    for block in func.blocks:
        print(f"  Basic block at 0x{block.addr:x}, size: {block.size} bytes")
        count += 1    
        # Optionally, you can print out the instructions in the block using capstone
        # for ins in block.capstone.insns:
print(count)
entry_point = proj.loader.main_object.entry
base_addr = proj.loader.main_object.mapped_base
print(f"Entry point: 0x{entry_point:x}")
# print(f"Base address: 0x{base_addr:x}")
# print(f"Binary size: {proj.loader.main_object.max_addr - proj.loader.main_object.min_addr} bytes")
# distance = dict(nx.shortest_path_length(cfg2.graph, source=entry_point))
# print(distance)
source_node = next((node for node in cfg2.graph.nodes() if node.addr == entry_point), None)
if source_node is None:
    print("Error: Entry point not found in the CFG.")
    # sys.exit(1)
distance = dict(nx.shortest_path_length(cfg2.graph, source=source_node))

definitions_not_in_cfg = set()
def_use_chains_not_in_cfg = set()
external_defs_not_in_cfg = set()
all_def_use_chains = set()

critical_registers = ['pc', 'sp', 'lr', 'cpsr']
critical_memory_ranges = [
    (0x400E0800, 0x400E0FFF),  # System Control registers
    # Add other critical ranges as per the datasheet
]

def is_hardware_address(addr):
    # Peripheral memory space for SAM3X8E
    hardware_ranges = [
        (0x40000000, 0x5FFFFFFF),
    ]
    for start, end in hardware_ranges:
        if addr >= start and addr <= end:
            return True
    return False

def is_critical_memory(addr):
    for start, end in critical_memory_ranges:
        if addr >= start and addr <= end:
            return True
    return False

block_count = {}
external_not_in_cfg = set()
def_not_in_cfg = set()
def__not_in_cfg = set()
all_chains = set()

# For storing the final results, keyed by the "definition block address."
# Each block will have a list of definitions, and each definition has a list of uses.
def_use_dict = {}

for function_addr, function in cfg2.kb.functions.items():
    try:
        print(f"\nAnalyzing function {function.name} at 0x{function_addr:x}")

        # ReachingDefinitions analysis
        rd_analysis = proj.analyses.ReachingDefinitions(
            subject=function,
            func_addr=function_addr,
            track_tmps=True,
            observe_all=True
        )

        for _def in rd_analysis.all_definitions:
            def_ins_addr = _def.codeloc.ins_addr
            uses = rd_analysis.all_uses.get_uses(_def)

            # 1) Skip external definitions
            if isinstance(_def.codeloc, ExternalCodeLocation):
                atom = _def.atom
                if isinstance(atom, MemoryLocation):
                    atom_id = ('mem', atom.addr)
                elif isinstance(atom, Register):
                    atom_id = ('reg', atom.reg_offset)
                else:
                    atom_id = ('other', str(atom))
                uses_ins_addrs = tuple(hex(use.ins_addr) for use in uses)
                external_not_in_cfg.add((atom_id, uses_ins_addrs))
                continue

            # 2) Find the CFG node & block for the definition
            def_node = cfg2.model.get_any_node(def_ins_addr, anyaddr=True)
            if def_node is None:
                def_not_in_cfg.add((hex(def_ins_addr), 'Def instruction not in CFG'))
                continue

            def_block = proj.factory.block(def_node.addr)

            # Ensure we have a record for this block in def_use_dict
            if def_block.addr not in def_use_dict:
                def_use_dict[def_block.addr] = {
                    "defs": []  # we will store multiple definitions for this block
                }

            # Create a new dict representing this *single definition*, plus its uses
            def_info = {
                "def_ins_addr": def_ins_addr,
                "uses": []  # We'll populate this with info about each use
            }
            def_use_dict[def_block.addr]["defs"].append(def_info)

            for use in uses:
                use_ins_addr = use.ins_addr
                all_chains.add((hex(def_ins_addr), hex(use_ins_addr)))

                use_node = cfg2.get_any_node(use_ins_addr, anyaddr=True)
                if use_node is None:
                    # Use instruction not in CFG
                    def__not_in_cfg.add((hex(def_ins_addr), hex(use_ins_addr), 'Use not in CFG'))
                    # Record the use with no block
                    def_info["uses"].append({
                        "use_ins_addr": use_ins_addr,
                        "use_block_addr": None,  # not in CFG
                    })
                    continue

                use_block = proj.factory.block(use_node.addr)

                # Check if there is a path from def_node to use_node
                path_exists = True
                if def_node != use_node:
                    if not nx.has_path(cfg2.graph, def_node, use_node):
                        path_exists = False
                        def__not_in_cfg.add(
                            (hex(def_ins_addr), hex(use_ins_addr), 'No path from def to use')
                        )

                # We do store it anyway, but if you want to skip uses with no path, you can do so here
                def_info["uses"].append({
                    "use_ins_addr": use_ins_addr,
                    "use_block_addr": use_block.addr,
                })

                # Update block count for the definition & use block
                block_count[def_block.addr] = block_count.get(def_block.addr, 0) + 1
                block_count[use_block.addr] = block_count.get(use_block.addr, 0) + 1

    except Exception as e:
        print(f"Error analyzing function {function.name} (0x{function_addr:x}): {e}")


output_filename = "block_def_use_buggycode.txt"
with open(output_filename, "w") as f:
    for block_addr, data in def_use_dict.items():
        f.write(f"block: 0x{block_addr:x}\n")
        for d in data["defs"]:
            def_addr_hex = f"0x{d['def_ins_addr']:x}"
            f.write(f"  def: {def_addr_hex}\n")

            # Gather all use ins-addrs and use-block-addrs
            use_ins_list = []
            use_block_list = []
            for u in d["uses"]:
                use_ins_list.append(f"0x{u['use_ins_addr']:x}")
                if u["use_block_addr"] is not None:
                    use_block_list.append(f"0x{u['use_block_addr']:x}")
                else:
                    use_block_list.append("(Not in CFG)")

            # Print them as comma-separated
            if use_ins_list:
                f.write(f"    use: {', '.join(use_ins_list)}\n")
            else:
                f.write("    use: (none)\n")

            if use_block_list:
                f.write(f"    use_block: {', '.join(use_block_list)}\n")
            else:
                f.write("    use_block: (none)\n")

f"\nDone! Wrote the block/def/use summary to {output_filename}."

print("\n=== Def-Use Summary ===")
for def_block_addr, info in def_use_dict.items():
    print(info["def_info"])
    print("  Uses in CFG (with path):")
    for u in info["uses_in_cfg"]:
        print(f"    - {u}")
    print("  Uses in CFG (no path):")
    for u in info["uses_no_path"]:
        print(f"    - {u}")
    print("  Uses not in CFG:")
    for u in info["uses_not_in_cfg"]:
        print(f"    - {u}")
    print()

    import re

# Suppose you already have def_use_dict in this structure:
# def_use_dict[def_block_addr] = {
#     "def_info": "DefBlock=0x..., size=...", 
#     "uses_in_cfg": [...],
#     "uses_no_path": [...],
#     "uses_not_in_cfg": [...]
# }

final_dict = {}

for def_block_addr, info in def_use_dict.items():
    # 'def_block_addr' is an integer (the block’s address).
    # We'll store it in hex form as the dictionary key.
    def_key = f"0x{def_block_addr:x}"

    # We only want the addresses from the "uses_in_cfg" (or from all sets if you prefer).
    uses_list = info["uses_in_cfg"]

    # Build a set to avoid duplicates.
    use_addr_set = set()

    # Each entry in uses_in_cfg might look like: "UseBlock=0x1234, size=16"
    # We'll parse out the actual hex address (0x1234).
    for use_entry in uses_list:
        # A simple regex or split can do the job. 
        # For example, let's capture the "0x..." part after "UseBlock=".
        # e.g. "UseBlock=0x1234, size=16"
        match = re.search(r'UseBlock=(0x[0-9a-fA-F]+)', use_entry)
        if match:
            raw_hex = match.group(1)  # e.g. "0x1234"
            use_addr_set.add(raw_hex)

    # Convert that set to a sorted list (optional)
    use_addr_list = sorted(use_addr_set)

    # Store it in the final dictionary
    final_dict[def_key] = use_addr_list

# Now 'final_dict' is something like:
# {
#   '0x1000': ['0x1234', '0x1280'],
#   '0x1100': ['0x2345'],
#   ...
# }

# Write it to "block.txt" in a simple format. You could use JSON or just str(...).
with open("block.txt", "w") as f:
    # For a nice human-readable format, you might do:
    for definition_addr, use_addrs in final_dict.items():
        
        for ua in use_addrs:
            f.write(f"Definition: {definition_addr}\n")
            f.write("Use:")
            f.write(f" {ua}\n")
        f.write("\n")
    
    # Or, if you just want a dictionary dump, do:
    # import json
    # json.dump(final_dict, f, indent=2)
