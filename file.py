import pefile
from logger import *

def read_file(file):
    with open(file, "rb") as file:
        return file.read()
    
def read_pe_string(file, address):
    offset = get_file_offset(file, address)

    file_data = read_file(file)
    if (file_data[offset + 1]): # check if unicode or ascii string
        return read_ascii_string(file_data, offset)
    else:
        return read_unicode_string(file_data, offset)

def get_file_offset(file, address):
    pe = pefile.PE(file)
    
    for section in pe.sections:
        section_address = section.VirtualAddress
        section_size = section.Misc_VirtualSize
        
        if(section_address <= address < section_address + section_size + pe.OPTIONAL_HEADER.ImageBase):
            return section.PointerToRawData + (address - section_address - pe.OPTIONAL_HEADER.ImageBase)
    
def read_ascii_string(data, offset):
    result = []

    while(data[offset]):
        result.append(chr(data[offset]))
        offset += 1

    return "".join(result)

def read_unicode_string(data, offset):
    result = []

    while(data[offset] or data[offset + 1]):
        result.append(chr(data[offset]))
        offset += 2

    return "".join(result)