import angr
import sys
import struct
import networkx as nx
import monkeyhex
import logging
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation

# Enable logging
logging.getLogger('angr').setLevel(logging.INFO)

# Path to the binary
binary_path = '/home/kai/project/experimentdata/FREERTOS.bin'

# Arduino Due base address for Flash memory
base_addr = 0x00080000

# Step 1: Extract the entry point and interrupt handlers from the vector table
with open(binary_path, 'rb') as f:
    vector_table_size = 256  # Adjust size as needed
    vector_table = f.read(vector_table_size)
    vector_count = len(vector_table) // 4
    if vector_count < 2:
        print("Error: Binary file is too short to contain a valid vector table.")
        sys.exit(1)
    vector_addresses = struct.unpack('<' + 'I' * vector_count, vector_table)
    initial_sp = vector_addresses[0]
    reset_handler = vector_addresses[1]
    entry_point = reset_handler + base_addr
    # Extract other handlers, ignoring invalid entries (e.g., 0xFFFFFFFF)
    interrupt_handlers = [addr + base_addr for addr in vector_addresses[2:] if addr not in (0x00000000, 0xFFFFFFFF)]
    print(f"Initial Stack Pointer: 0x{initial_sp:08X}")
    print(f"Entry Point (Reset Handler) address: 0x{entry_point:08X}")
    print(f"Interrupt handlers at addresses: {[hex(addr) for addr in interrupt_handlers]}")

# Step 2: Load the binary with correct base address and entry point
p = angr.Project(
    binary_path,
    main_opts={
        'backend': 'blob',
        'arch': 'armel',  # Confirm this matches your binary
        'base_addr': base_addr,
        'entry_point': entry_point,
    },
    auto_load_libs=False
)

# List of known starting addresses
additional_starts = [entry_point] + interrupt_handlers

# Step 3: Generate the CFG using CFGEmulated
cfg = p.analyses.CFGEmulated(
    starts=additional_starts,
    context_sensitivity_level=3,
    keep_state=True,
    state_add_options=angr.sim_options.refs | {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    normalize=True,
    enable_function_hints=True
)

# Define critical registers and memory ranges
critical_registers = ['pc', 'sp', 'lr', 'cpsr']
critical_memory_ranges = [
    (0x400E0800, 0x400E0FFF),  # System Control registers
    # Add other critical ranges as per the datasheet
]

def is_hardware_address(addr):
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

# Sets to store unique definitions and def-use chains not in CFG
definitions_not_in_cfg = set()
def_use_chains_not_in_cfg = set()
external_defs_not_in_cfg = set()

def get_block_containing_insn(cfg, ins_addr):
    node = cfg.get_any_node(ins_addr, anyaddr=True)
    if node:
        return node
    else:
        for n in cfg.graph.nodes():
            if n.block and n.block.addr <= ins_addr < n.block.addr + n.block.size:
                return n
    return None

# Step 4: Iterate over all functions in the CFG
for function_addr, function in cfg.kb.functions.items():
    try:
        print(f"\nAnalyzing function {function.name} at 0x{function_addr:x}")

        # Create an initial state for the function
        state = p.factory.blank_state(
            addr=function_addr,
            add_options=angr.sim_options.refs | {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
        )
        state.regs.sp = initial_sp  # Set the stack pointer

        # Run ReachingDefinitions analysis on the function
        rd_analysis = p.analyses.ReachingDefinitions(
            subject=function,
            func_addr=function_addr,
            init_state=state,
            track_tmps=True,
            observe_all=True
        )

        # Iterate over all definitions
        for _def in rd_analysis.all_definitions:
            def_ins_addr = _def.codeloc.ins_addr
            uses = rd_analysis.all_uses.get_uses(_def)

            # Check if the definition is external
            if isinstance(_def.codeloc, ExternalCodeLocation):
                atom = _def.atom
                # Create a hashable identifier for the atom
                if isinstance(atom, MemoryLocation):
                    atom_id = ('mem', atom.addr)
                elif isinstance(atom, Register):
                    atom_id = ('reg', atom.reg_offset)
                else:
                    atom_id = ('other', str(atom))
                # Use the instruction addresses of uses
                uses_ins_addrs = tuple(use.ins_addr for use in uses)
                external_defs_not_in_cfg.add((atom_id, uses_ins_addrs))
                continue  # Continue processing if needed

            # Get the CFG node containing the definition instruction address
            def_node = get_block_containing_insn(cfg, def_ins_addr)
            if def_node is None:
                # Record the definition not in CFG
                definitions_not_in_cfg.add((def_ins_addr, 'Def instruction not in CFG'))
                continue  # Skip further processing for this definition

            # Handle uses
            if uses:
                for use in uses:
                    use_ins_addr = use.ins_addr
                    use_node = get_block_containing_insn(cfg, use_ins_addr)
                    if use_node is None:
                        # Record the def-use chain not in CFG
                        def_use_chains_not_in_cfg.add((def_ins_addr, use_ins_addr, 'Use instruction not in CFG'))
                        continue  # Continue to next use

                    # Check if there is a path from def_node to use_node
                    if def_node != use_node:
                        try:
                            # Attempt to find a path in the CFG
                            if not nx.has_path(cfg.graph, def_node, use_node):
                                # Record the def-use chain with no path in CFG
                                def_use_chains_not_in_cfg.add((def_ins_addr, use_ins_addr, 'No path from def to use in CFG'))
                                continue  # Continue to next use
                        except nx.NetworkXError as e:
                            # Handle exceptions in path finding
                            def_use_chains_not_in_cfg.add((def_ins_addr, use_ins_addr, f'Error finding path: {e}'))
            else:
                # No uses recorded
                pass

    except Exception as e:
        print(f"Error analyzing function {function.name} (0x{function_addr:x}): {e}")

# Step 5: Print definitions not included in the CFG
print("\nDefinitions not included in the CFG:")
for def_ins_addr, reason in definitions_not_in_cfg:
    if def_ins_addr is not None:
        def_ins_addr_str = f"0x{def_ins_addr:x}"
    else:
        def_ins_addr_str = "Unknown"

    print(f"Definition at instruction address: {def_ins_addr_str} - Reason: {reason}")

print(f"Total number of definitions not in CFG: {len(definitions_not_in_cfg)}")

# Step 6: Print def-use chains not included in the CFG
print("\nDef-use chains not included in the CFG or without control flow path:")
for def_ins_addr, use_ins_addr, reason in def_use_chains_not_in_cfg:
    if def_ins_addr is not None:
        def_ins_addr_str = f"0x{def_ins_addr:x}"
    else:
        def_ins_addr_str = "Unknown"
    if use_ins_addr is not None:
        use_ins_addr_str = f"0x{use_ins_addr:x}"
    else:
        use_ins_addr_str = "Unknown"

    print(f"Definition at instruction address: {def_ins_addr_str}")
    print(f"  Use at instruction address: {use_ins_addr_str} - Reason: {reason}")

print(f"Total number of def-use chains not in CFG: {len(def_use_chains_not_in_cfg)}")

# Step 7: Print external definitions in def-use chains not included in CFG
print("\nExternal definitions involved in def-use chains not included in CFG:")
for atom_id, uses_ins_addrs in external_defs_not_in_cfg:
    atom_type, atom_value = atom_id
    if atom_type == 'mem':
        print(f"External MemoryLocation at address: {hex(atom_value)}")
    elif atom_type == 'reg':
        reg_name = p.arch.register_names.get(atom_value, f"Unknown({atom_value})")
        print(f"External Register: {reg_name}")
    else:
        print(f"External Atom: {atom_value}")

    # Print uses if any
    if uses_ins_addrs:
        for use_ins_addr in uses_ins_addrs:
            if use_ins_addr is not None:
                use_ins_addr_str = f"0x{use_ins_addr:x}"
            else:
                use_ins_addr_str = "Unknown"
            print(f"  Used at instruction address: {use_ins_addr_str}")
    else:
        print("  No uses recorded.")

print(f"Total number of external definitions not in CFG: {len(external_defs_not_in_cfg)}")
