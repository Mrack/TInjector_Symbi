#!/usr/bin/env python3
import sys

def bin_to_header(bin_file, header_file, array_name):
    with open(bin_file, 'rb') as f:
        data = f.read()

    with open(header_file, 'w') as f:
        f.write(f"// Auto-generated from {bin_file}\n")
        f.write(f"#ifndef {array_name.upper()}_H\n")
        f.write(f"#define {array_name.upper()}_H\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"uint8_t {array_name}[] = {{\n")

        for i, byte in enumerate(data):
            if i % 12 == 0:
                f.write("    ")
            f.write(f"0x{byte:02x}, ")
            if (i + 1) % 12 == 0:
                f.write("\n")

        f.write("\n};\n\n")
        f.write(f"const size_t {array_name}_size = {len(data)};\n\n")
        f.write(f"#endif // {array_name.upper()}_H\n")

if __name__ == '__main__':
    bin_to_header(sys.argv[1], sys.argv[2], sys.argv[3])
