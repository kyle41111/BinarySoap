import pefile
import sys
import os
import struct

def calculate_checksum(pe):

    checksum = 0
    file_data = bytearray(pe.write())
    checksum_offset = pe.DOS_HEADER.e_lfanew + 88
    file_data[checksum_offset:checksum_offset + 4] = b'\x00\x00\x00\x00'
    words = struct.unpack('<' + 'H' * (len(file_data) // 2), file_data[:len(file_data) & ~1])
    checksum = sum(words)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    checksum = checksum & 0xFFFF
    checksum += len(file_data)
    return checksum

def scrub_binary(input_file, output_file):
    
    if not os.path.isfile(input_file):
        print(f"Error: File not found: {input_file}")
        return False
    
    try:
        print(f"Loading PE file: {input_file}")
        pe = pefile.PE(input_file, fast_load=False)
        pe.parse_data_directories()
        
        # Modification 1: Strip debug directory (-0.482506 impact)
        print("Stripping debug directory")
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size = 0
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                dbg_offset = dbg.struct.PointerToRawData
                size = dbg.struct.SizeOfData
                if dbg_offset and size:
                    pe.set_bytes_at_offset(dbg_offset, b'\x00' * size)
        
        
        print("Zeroing linker version")
        pe.OPTIONAL_HEADER.MajorLinkerVersion = 0
        pe.OPTIONAL_HEADER.MinorLinkerVersion = 0
        print("Zeroing COFF TimeDateStamp")
        if hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
            pe.FILE_HEADER.TimeDateStamp = 0
			
        print("Recalculating valid checksum")
        pe.OPTIONAL_HEADER.CheckSum = calculate_checksum(pe)
        
        # Write the modified file
        print(f"Writing modified file: {output_file}")
        pe.write(output_file)
        
        print(f"Successfully created: {output_file}")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python binarysoap.py <input_file> <output_file>")
        print("Example: python binarysoap.py malicious.dll clean.dll")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if scrub_binary(input_file, output_file):
        sys.exit(0)
    else:
        sys.exit(1)
