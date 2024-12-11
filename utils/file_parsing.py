import logging as log

def parse_def_use_file(filename='def_use1.txt'):
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
