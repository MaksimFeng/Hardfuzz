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

# if __name__ == "__main__":
#     # Parse def-use file
#     # defs = parse_def_use_file()
#     # print(defs)
    
#     # Parse external file
#     externals = parse_external()
#     print(externals)

def parse_block(filename = 'block.txt'):
    with open(filename, 'r') as f:
        block = [line.strip() for line in f]
    return block