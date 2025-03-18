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
binary2_path = '/home/kai/Arduino/program1_json/build/arduino.sam.arduino_due_x_dbg/program1_json.ino.elf'
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