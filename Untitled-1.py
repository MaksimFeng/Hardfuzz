import angr
import sys
import struct  # For unpacking binary data
import monkeyhex  # For better hexadecimal representation in outputs

# Path to the binary
binary_path = '/home/kai/project/experimentdata/FREERTOS.bin'

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

#  Load the binary with correct base address and entry point
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
print("Loaded binary:", p.loader)

# Dictionary to store ReachingDefinitions results
rd_results = {}

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

        # Store RD results
        rd_results[function_addr] = rd_analysis

        # Iterate over all definitions and their uses
        print(f"Definitions and uses in function {function.name} (0x{function_addr:x}):")
        for _def in rd_analysis.all_definitions:
            uses = rd_analysis.all_uses.get_uses(_def)
            if uses:
                print(f"Definition at {_def.codeloc}:")
                for use in uses:
                    print(f"  Used at {use}")
            else:
                print(f"Definition at {_def.codeloc} has no uses.")

    except Exception as e:
        print(f"Error analyzing function {function.name} (0x{function_addr:x}): {e}")
