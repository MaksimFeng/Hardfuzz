import angr
import sys
import struct
import networkx as nx
import monkeyhex
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation

# Path to the binary
binary_path = '/home/kai/experimentdata/FREERTOS.bin'

# Arduino Due base address for Flash memory
base_addr = 0x00080000

# Step 1: Extract the entry point from the vector table
with open(binary_path, 'rb') as f:
    # Read the first 8 bytes (Initial Stack Pointer and Reset Handler)
    vector_table = f.read(8)
    if len(vector_table) < 8:
        print("Error: Binary file is too short to contain a valid vector table.")
        sys.exit(1)
    # Unpack the data (little-endian format)
    initial_sp, reset_handler = struct.unpack('<II', vector_table)
    entry_point = reset_handler
    print(f"Initial Stack Pointer: 0x{initial_sp:08X}")
    print(f"Entry Point (Reset Handler) address: 0x{entry_point:08X}")

# Step 2: Load the binary with correct base address and entry point
p = angr.Project(
    binary_path,
    main_opts={
        'backend': 'blob',
        'arch': 'armel',  # 'armel' for little-endian ARM
        'base_addr': base_addr,
        'entry_point': entry_point,
    },
    auto_load_libs=False
)

# Step 3: Generate the CFG
cfg = p.analyses.CFGFast(normalize=True, data_references=True)

# Collect all addresses from the CFG nodes
cfg_nodes = {}
for node in cfg.graph.nodes():
    if hasattr(node, 'addr') and node.addr is not None:
        cfg_nodes[node.addr] = node

print(f"Total nodes in CFG: {len(cfg_nodes)}")

# Define critical registers and memory ranges
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

# Lists to store definitions not in CFG and external definitions
definitions_not_in_cfg = []
external_defs_not_in_cfg = []

# Step 4: Iterate over all functions in the CFG
for function_addr, function in cfg.kb.functions.items():
    try:
        print(f"\nAnalyzing function {function.name} at 0x{function_addr:x}")

        # Run ReachingDefinitions analysis on the function
        rd_analysis = p.analyses.ReachingDefinitions(
            subject=function,
            func_addr=function_addr,
            track_tmps=True,
            observe_all=True  # Observe all definitions and uses
        )

        # Iterate over all definitions
        for _def in rd_analysis.all_definitions:
            def_ins_addr = _def.codeloc.ins_addr
            uses = rd_analysis.all_uses.get_uses(_def)

            # Check if the definition is external
            if isinstance(_def.codeloc, ExternalCodeLocation):
                atom = _def.atom
                # Collect external definitions involved in def-use chains not included in CFG
                external_defs_not_in_cfg.append((_def, uses))

                # You can also print details here if desired
                continue  # Continue processing if needed

            # Proceed with your existing logic for definitions within the code
            # Determine the basic block of the definition
            def_block_addr = _def.codeloc.block_addr

            # Check if the definition's basic block is in the CFG
            if def_block_addr not in cfg_nodes:
                definitions_not_in_cfg.append((_def, uses, 'Def block not in CFG'))
                continue  # Skip further processing for this definition

            # Handle uses
            if uses:
                for use in uses:
                    use_ins_addr = use.ins_addr
                    use_block_addr = use.block_addr

                    # Check if the use's basic block is in the CFG
                    if use_block_addr not in cfg_nodes:
                        definitions_not_in_cfg.append((_def, uses, 'Use block not in CFG'))
                        break  # No need to check further uses for this definition

                    # Check if there is a path from def_block to use_block
                    def_node = cfg_nodes[def_block_addr]
                    use_node = cfg_nodes[use_block_addr]

                    if def_block_addr != use_block_addr:
                        if not nx.has_path(cfg.graph, def_node, use_node):
                            definitions_not_in_cfg.append((_def, uses, 'No path from def to use in CFG'))
                            break
            else:
                # No uses recorded
                pass

    except Exception as e:
        print(f"Error analyzing function {function.name} (0x{function_addr:x}): {e}")

# Step 5: Print definitions and uses not included in the CFG
print("\nDefinitions and uses not included in the CFG or without control flow path:")
for _def, uses, reason in definitions_not_in_cfg:
    def_ins_addr = _def.codeloc.ins_addr
    if def_ins_addr is not None:
        def_ins_addr_str = f"0x{def_ins_addr:x}"
    else:
        def_ins_addr_str = "Unknown"

    print(f"Definition at {_def.codeloc} (instruction address: {def_ins_addr_str}) - Reason: {reason}")
    if uses:
        for use in uses:
            use_ins_addr = use.ins_addr
            if use_ins_addr is not None:
                use_ins_addr_str = f"0x{use_ins_addr:x}"
            else:
                use_ins_addr_str = "Unknown"
            print(f"  Use at {use} (instruction address: {use_ins_addr_str})")
    else:
        print("  No uses recorded.")

# Step 6: Print external definitions in def-use chains not included in CFG
print("\nExternal definitions involved in def-use chains not included in CFG:")
for _def, uses in external_defs_not_in_cfg:
    atom = _def.atom
    if isinstance(atom, MemoryLocation):
        addr = atom.addr
        print(f"External MemoryLocation at address: {hex(addr)}")
    elif isinstance(atom, Register):
        reg_offset = atom.reg_offset
        reg_name = p.arch.register_names.get(reg_offset, f"Unknown({reg_offset})")
        print(f"External Register: {reg_name}")
    else:
        print(f"External Atom of type {type(atom)}")

    # Print uses if any
    if uses:
        for use in uses:
            use_ins_addr = use.ins_addr
            if use_ins_addr is not None:
                use_ins_addr_str = f"0x{use_ins_addr:x}"
            else:
                use_ins_addr_str = "Unknown"
            print(f"  Used at instruction address: {use_ins_addr_str}")
    else:
        print("  No uses recorded.")