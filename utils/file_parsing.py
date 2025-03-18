import logging as log
import re

def parse_def_use_file(filename='block.txt'):
    def_dict = {}
    try:
        with open(filename, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        log.error(f"Definition-Use file '{filename}' not found.")
        return []

    i = 0
    while i < len(lines):
        if lines[i].startswith("Definition:"):
            def_line = lines[i]
            use_line = lines[i+1] if i+1 < len(lines) and lines[i+1].startswith("Use:") else None
            if use_line:
                def_addr_str = def_line.split()[-1]
                use_addr_str = use_line.split()[-1]
                if def_addr_str not in def_dict:
                    def_dict[def_addr_str] = []
                def_dict[def_addr_str].append(use_addr_str)
                i += 2
            else:
                i += 1
        else:
            i += 1

    sorted_defs = sorted(def_dict.items(), key=lambda x: len(x[1]), reverse=True)
    return sorted_defs

def parse_external(filename='external1.txt'):
    groups = []
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        log.error(f"Definition-Use file '{filename}' not found.")
        return []
    
    current_def = None
    current_uses = []
    
    def save_group():
        nonlocal current_def, current_uses
        # 如果定义为空且有使用，将第一个 use 移到定义位置
        if current_def == "" and current_uses:
            current_def = current_uses.pop(0)
        groups.append((current_def, current_uses))
    
    for line in lines:
        # 跳过空行
        if not line.strip():
            continue
        
        # 保留原始行，不去除前导空格，用于判断是否缩进
        stripped = line.strip()
        
        # 判断是否为 use 行：如果行有缩进或以 "Uses:" 开头
        if line[0] in (' ', '\t') or stripped.startswith("Uses:"):
            # 如果以 "Uses:" 开头，则去掉前缀
            if stripped.startswith("Uses:"):
                use_value = stripped[len("Uses:"):].strip()
            else:
                use_value = stripped
            current_uses.append(use_value)
        else:
            # 遇到新的定义行，将前一个分组保存
            if current_def is not None or current_uses:
                save_group()
            # 判断定义行内容：如果以 "0x" 开头，则保留；否则留空
            if stripped.startswith("0x"):
                current_def = stripped
            else:
                current_def = ""
            current_uses = []
    
    # 保存最后一个分组
    if current_def is not None or current_uses:
        save_group()
    
    # 按使用数量降序排序
    groups.sort(key=lambda x: len(x[1]), reverse=True)
    return groups

def parse_block_with_full_details(filename='block_def_use.txt'):
    """
    Reads a file in the format:
        block: 0xBLOCK_ADDR
          def: 0xDEF_ADDR
            use: 0xUSE_ADDR, 0xUSE_ADDR
            use_block: 0xBLOCK_ADDR, 0xBLOCK_ADDR
          def: 0xDEF_ADDR
            use: ...
            use_block: ...
        block: 0xANOTHER_BLOCK
        ...

    Returns a dict of:
  
      "<block_addr>": [
        {
          "def_addr": "<def_addr>",
          "use_addrs": [<list of addresses>],
          "use_block_addrs": [<list of block addresses>]
        },
        ...
   
    """
    data = {}
    try:
        with open(filename, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log.error(f"File '{filename}' not found.")
        return {}

    current_block = None
    current_def_dict = None  # Will be a dict with keys 'def_addr', 'use_addrs', 'use_block_addrs'

    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("block:"):
            # Example: "block: 0x1234"
            _, block_addr = line.split("block:", 1)
            block_addr = block_addr.strip()  # e.g. "0x1234"
            current_block = block_addr
            # Ensure we have an empty list for this block
            if current_block not in data:
                data[current_block] = []
            i += 1

        elif line.startswith("def:"):
            # Example: "def: 0x5678"
            _, def_addr = line.split("def:", 1)
            def_addr = def_addr.strip()
            # Create a new structure for the current definition
            current_def_dict = {
                'def_addr': def_addr,
                'use_addrs': [],
                'use_block_addrs': []
            }
            # Add this def to the current block’s list
            if current_block is not None:
                data[current_block].append(current_def_dict)
            i += 1

        elif line.startswith("use:"):
            # Example: "use: 0x1240, 0x1244"
            _, use_str = line.split("use:", 1)
            use_str = use_str.strip()
            # Split by comma
            uses = [u.strip() for u in use_str.split(",")]
            if current_def_dict is not None:
                current_def_dict['use_addrs'].extend(uses)
            i += 1

        elif line.startswith("use_block:"):
            # Example: "use_block: 0x1240, 0x1244"
            _, use_block_str = line.split("use_block:", 1)
            use_block_str = use_block_str.strip()
            # Split by comma
            use_blocks = [u.strip() for u in use_block_str.split(",")]
            if current_def_dict is not None:
                current_def_dict['use_block_addrs'].extend(use_blocks)
            i += 1

        else:
            # Unrecognized line => skip or handle differently as needed
            i += 1

    return data


def parse_block(filename = 'block.txt'):
    with open(filename, 'r') as f:
        block = [line.strip() for line in f]
    return block

# if __name__ == "__main__":  # 修正双下划线
#     result = parse_block_with_full_details("../block_def_use.txt")
#     for block, def_list in result.items():
#         print(f"BLOCK {block}")
#         print(len(def_list))
#         # for d in def_list:
        #     print(f"    Def {d['def_addr']}")  # 修正字典访问
        #     print(f"        uses: {d['use_addrs']}")
        #     print(f"        use_block: {d['use_block_addrs']}")