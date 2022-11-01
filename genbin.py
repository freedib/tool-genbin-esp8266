#!/usr/bin/env python

# Tool used for generate bin images OTA and non OTAfor ESP8266
# It is a mix of esptool-ck and Espressif's gen_appbin.py
# Copyright Didier Bertrand (https://github.com/freedib), January 2021
#
# The tool extract the sections from the elf file and generate:
#     flash.bin + irom0.text.bin or user1.bin/user2.bin
#
# No intermediate file are created and no external tool are required
#
# Args are positionnal and similar to esptool.py
# Examples (notice tha args are positional):
#     generate firmware.bin and firmware.bin.irom0text.bin
#         genbin 0 dio 40m 4MB-c1 firmware.elf firmware.bin firmware.bin.irom0text.bin")
#     generate user1.16384.new.9.bin 
#         genbin 1 dio 40m 16MB firmware.elf user1.16384.new.9.bin") 
#     generate user2.4096.new.6.bin 
#         genbin 2 dio 40m 4MB-c1 firmware.elf user2.4096.new.6.bin") 
#     generate user1.16384.new.9.bin 
#         genbin 1 dio 40m 16MB firmware.elf user1.16384.new.9.bin") 
#     generate user1.bin and user2.bin 
#         genbin 12 dio 40m 16MB firmware.elf user1.bin user2.bin") 

 
import os, sys, string, struct, zlib


############ ELF extraction (from esptool-ck) ############

# get string at offset sh_name in strings
# returns the string
def get_elf_string(sh_name, strings):
    pythonstring = ''
    if len(strings)==0 or sh_name==0:
        return ''
    for c in range(sh_name,len(strings)):
        if strings[c] == 0:
            break
        pythonstring = pythonstring+chr(strings[c])
    return pythonstring

# get one section index
# return a tuple with (name, offset, size, address)
def get_elf_section (e_shndx,e_shoff,e_shentsize):
    global cstrings
    # read one elf section
    offset = e_shoff + e_shndx*e_shentsize
    # print(("Section %s: offset=%s(%s)") % (e_shndx,offset,hex(offset)), end=' ')
    elf_fd.seek(offset)
    data = elf_fd.read(40);
    # read section header
    # see Elf32_Shdr in esptool-ck for fields
    elf_section = struct.Struct("<IIIIIIIIII").unpack(data)
    sh_name = elf_section[0]
    sh_addr = elf_section[3]
    sh_offset = elf_section[4]
    sh_size = elf_section[5]
    section_name = get_elf_string(sh_name,cstrings)
    # print(("name=%s, sh_name=%s, sh_offset=%s, offset=%s, sh_addr=%s, sh_size=%s") %
    #      (section_name,hex(sh_name),hex(sh_offset),hex(offset),hex(sh_addr),sh_size))
    return ((section_name,sh_offset,sh_size,sh_addr))       # name, size, offset, address

# extract a section by index from elf and return it
# return a tuple with (data, address)
def read_elf_section_by_index (e_shndx):
    if sections[e_shndx][2] > 0:                    # size
        elf_fd.seek(sections[e_shndx][1])           # offset
        data = elf_fd.read(sections[e_shndx][2]);   # size
        return (data, sections[e_shndx][3])         # address

# extract a section by name from elf and return it
# return a tuple with (data, address)
def read_elf_section_by_name (section_name,filename=None):
    for e_shndx in range(0,len(sections)):
        if sections[e_shndx][0] == section_name:            # name
            return read_elf_section_by_index (e_shndx)

# extract a section by name from elf and save it if filename is furnished
def extract_elf_section_by_name (section_name, filename):
    section = read_elf_section_by_name (section_name)
    if filename != None:
        section_fd = open(filename, "wb")
        if section_fd:
            section_fd.write(section[0])
            section_fd.close()
        else:
            print ('%s write fail\n'%(filename))

# search a symbol by name dans return its definition
# see Elf32_Sym in esptool-ck for fields
def search_elf_symbol (name):
    global strtab, symtab
    if not strtab:
        strtab = (read_elf_section_by_name('.strtab'))[0]
    if not symtab:
        symtab = (read_elf_section_by_name('.symtab'))[0]

    for entry in range(0,len(symtab),16):
        symbol = struct.Struct("<IIIBBH").unpack(symtab[entry:entry+16])
        symbol_name = get_elf_string(symbol[0],strtab)
        if (symbol_name==name):
            # print(("symbol=%s, name=%s, st_name=%s, st_size=%s, st_value=%s, st_info=%s, st_other=%s, st_shndx=%s") %
            #     (entry, get_elf_string(symbol[0],strtab), hex(symbol[0]),hex(symbol[1]),hex(symbol[2]),
            #     hex(symbol[3]),hex(symbol[4]),hex(symbol[5])))
            return symbol

# open elf file, extract main header, strings and sections indexes
def open_elf(elf_filename):
    # open the file
    global elf_fd
    global cstrings
    global sections
    global symtab
    global strtab
    
    elf_fd = open(elf_filename, "rb")
    elf_size = os.stat(elf_filename).st_size
    # print(("Parsing: %s Size: %s(%s)") % (elf_filename,elf_size,hex(elf_size)))
    # read elf header
    data = elf_fd.read(52);
    # see Elf32_Ehdr in esptool-ck for fields
    elf_header = struct.Struct("<IIIIHHIIIIIHHHHHH").unpack(data)
    e_shoff = elf_header[9]
    e_shentsize = elf_header[14]
    e_shnum = elf_header[15]
    e_shstrndx = elf_header[16]
    # print(("Sections: e_shnum=%s(%s) e_shoff=%s(%s) e_shentsize=%s(%s) e_shstrndx=%s(%s)") % 
    #       (e_shnum,hex(e_shnum),e_shoff,hex(e_shoff),e_shentsize,hex(e_shentsize),e_shstrndx,hex(e_shstrndx)))
    # get strings and sections
    cstrings = []
    sections = []
    sections.append(get_elf_section (e_shstrndx,e_shoff,e_shentsize))  # read strings section info
    cstrings = (read_elf_section_by_index(0))[0]                       # read strings
    sections = []
    for e_shndx in range(0,e_shnum):                                   # section 0 not used
        sections.append(get_elf_section (e_shndx,e_shoff,e_shentsize)) # name, size, offset, address
    symtab = None
    strtab = None
    
    # tests
    # search_elf_symbol ('call_user_start')
    # for e_shndx in range(0,e_shnum):
    #     symtab = read_elf_section_by_index(e_shndx)


def close_elf():
    elf_fd.close()



############ BIN creation (from gen_appbin) ############

CHECKSUM_INIT = 0xEF
chk_sum = CHECKSUM_INIT
total_bytes = 0

# append data to a file
def write_file(filename,data,clear_file=False):
    global total_bytes
    open_mode = 'ab'
    if clear_file:
        open_mode = 'wb'
    fp = open(filename,open_mode)
    if fp:
        fp.seek(0,os.SEEK_END)
        fp.write(data)
        # print(('+++  %s(0x%s) @ %s(0x%s) -> ')%
        #       (len(data), len(data),total_bytes, total_bytes),end=' ')
        total_bytes = total_bytes+len(data)
        # print(('%s(0x%s) == %s(0x%s)')%
         #      (total_bytes, total_bytes, fp.tell(), fp.tell()),end=' :: ')
        fp.close()

    else:
        print ('!!! %s write fail\n'%(filename))

# append a section to output file. crate a heade for this section ans compute checksum
def combine_bin(section_name,dest_filename,use_section_offset_addr,need_chk):
    global chk_sum

    section = read_elf_section_by_name(section_name)
    data_bin = section[0]
    if use_section_offset_addr:
        start_offset_addr = section[1]
    else:
        start_offset_addr = 0
    data_len = len(data_bin)
    if need_chk:
        section_len = (data_len + 3) & (~3)
    else:
        section_len = (data_len + 15) & (~15)
    header = struct.pack('<II',start_offset_addr,section_len)
    write_file(dest_filename,header)
    # print(('add header(%s) = %s (0x%s), %s (0x%s)')%(len(header), 
    #     start_offset_addr, hex(start_offset_addr), section_len, hex(section_len)))

    write_file(dest_filename,data_bin)

    if need_chk:
        for loop in range(len(data_bin)):
            chk_sum ^= ord(chr(data_bin[loop]))
    padding_len = section_len - data_len
    if padding_len:         # padding
        padding = [0]*padding_len
        write_file(dest_filename,bytes(padding))
        # print(('add padding(%s)')%(len(bytes(padding))))
        if need_chk:
            for loop in range(len(padding)):
                chk_sum ^= ord(chr(padding[loop]))
    print ('genbin.py: add section %s, size is %d, chk_sum=0x%s' %
        (section_name, section_len, hex(chk_sum)))

# compute the crc for the generated file
def getFileCRC(_path): 
    try: 
        blocksize = 1024 * 64 
        f = open(_path,"rb") 
        str = f.read(blocksize) 
        crc = 0 
        while(len(str) != 0): 
            crc = zlib.crc32(str, crc) 
            str = f.read(blocksize) 
        f.close() 
    except: 
        print ('get file crc error!' )
        return 0 
    return crc


BIN_MAGIC_FLASH  = 0xE9
BIN_MAGIC_IROM   = 0xEA

# bin formats (from esp8266_parse_bin.py)

# non ota: eagle.flash.bin (firmware.bin)  (ido-rtos)
# Header:  0xe9 3 0x2 0x90 0x40100004
# Segments:  .text, .data, .rodata
# Padding: 0-15 bytes + checksum

# ota: user1.16384.new.9.bin
# Header:  0xea 4 0x0 0x1 0x40100004
# Segment .irom0text         
# Header:  0xe9 3 0x2 0x90 0x40100004
# Segments:  .text, .data, .rodata
# Padding: 0-15 bytes + checksum
# Extra Data [no-header] of Length: 4 ->  0xe7 0x41 0x67 0x53 


# read rections from elf file and generate bin files
def gen_appbin (user_bin, flash_mode, flash_clk_div, flash_size_map, flash_filename, iron_filename=None): 
    
    global chk_sum
    chk_sum = CHECKSUM_INIT
    
    clear_file = True
    entry_symbol = search_elf_symbol('call_user_start')
    if entry_symbol:
        entry_addr = entry_symbol[1]
        # print("Entry addr = "+hex(entry_addr))
        
    if user_bin:        # add irom0ext to image
        header = struct.pack('<BBBBI',BIN_MAGIC_IROM,4,0,user_bin,entry_addr)
        sum_size = len(header)
        write_file(flash_filename,header,clear_file)
        clear_file = False
        # print(('add header(%s) = %s %s %s %s %s')%(len(header), hex(BIN_MAGIC_IROM),
        #         4, 0, user_bin, hex(entry_addr)))
        # irom0.text.bin
        combine_bin('.irom0.text',flash_filename,False,False)
        
    else:               # extract irom0ext
        extract_elf_section_by_name ('.irom0.text', iron_filename)
        
    byte2=int(flash_mode)&0xff
    byte3=(((int(flash_size_map)<<4)| int(flash_clk_div))&0xff)
    header = struct.pack('<BBBBI',BIN_MAGIC_FLASH,3,byte2,byte3,entry_addr)
    sum_size = len(header)
    write_file(flash_filename,header,clear_file)
    clear_file = False
    # print(('add header(%s) = %s %s %s %s %s')%
    #     (len(header), hex(BIN_MAGIC_FLASH), 3, hex(byte2), hex(byte3), hex(entry_addr)))
    combine_bin('.text',flash_filename,True,True)
    combine_bin('.data',flash_filename,True,True)
    combine_bin('.rodata',flash_filename,True,True)

    # write checksum header
    flash_data_line  = 16
    data_line_bits = 0xf

    sum_size = os.path.getsize(flash_filename) + 1
    sum_size = flash_data_line - (data_line_bits&sum_size)
    if sum_size:
        padding = [0]*(sum_size)
        write_file(flash_filename,bytes(padding))
        # print(('add padding(%s)')%(len(padding)))
        
    write_file(flash_filename,bytes([chk_sum&0xFF]))
    # print(('add chk=%s')%(chk_sum&0xFF))
 
    if user_bin:
        all_bin_crc = getFileCRC(flash_filename)
        print ('genbin.py: crc32 before inversion = %s, %d' % (hex(all_bin_crc), all_bin_crc))
        if sys.version_info.major >= 3:
            if all_bin_crc > 0x80000000:
                all_bin_crc = 0x100000000 - all_bin_crc - 1
            else:
                all_bin_crc = all_bin_crc + 1
        else:
            if all_bin_crc < 0:
                all_bin_crc = abs(all_bin_crc) - 1
            else :
                all_bin_crc = abs(all_bin_crc) + 1
        print ('genbin.py: crc32 after inversion = %s, %d' % (hex(all_bin_crc), all_bin_crc))
            
        # print (hex(all_bin_crc))
        bytes_all_bin_crc = struct.pack('<I',all_bin_crc)
        write_file(flash_filename,bytes_all_bin_crc)
        # print("")


############ Main ############

# return binary value for argument
def get_val (arg, choices, default):
    var = default
    try: 
        return choices.index(arg)
    except: 
        return choices.index(default)


def main(): 
     
    if len(sys.argv)<7 or len(sys.argv)>8:
        print("Format: genbin 0 flash_mode flash_clk_div flash_map_size file.elf flash.bin irom.bin")
        print("Format: genbin user_app flash_mode flash_clk_div flash_map_size file.elf user.bin ") 
        exit(0)
 
    user_app = sys.argv[1]              # 1 or 2
    flash_mode = get_val (sys.argv[2], ['qio','qout','dio','dout'], 'qio')
    flash_clk_div = get_val (sys.argv[3], ['40m','26m','20m','80m'], '40m')
    flash_size_map = get_val (sys.argv[4], ['512KB','256KB','1MB','2MB','4MB','2MB-c1','4MB-c1','4MB-c2','8MB','16MB'], '4MB-c2')
    elf_filename = sys.argv[5]

    open_elf (elf_filename)

    if len(sys.argv)==8 and user_app=='0':
        flash_filename = sys.argv[6]        # eagle.flash.bin
        iron_filename = sys.argv[7]         # eagle.irom0text.bin
        print(("genbin.py: %s --> create %s + %s") %
              (elf_filename, flash_filename, iron_filename))

        gen_appbin (0, flash_mode, flash_clk_div, flash_size_map, flash_filename, iron_filename)
        
    elif len(sys.argv)==7 and (user_app=='1' or user_app=='2'):
        user_file = sys.argv[6]        # user1.bin or user2.bin
        print(("genbin.py: create %s from %s") %
              (user_file, elf_filename))
        gen_appbin (int(user_app), flash_mode, flash_clk_div, flash_size_map, user_file)

    elif len(sys.argv)==8 and (user_app=='12'):     # generate user1 and user2 file 
        user1_filename = sys.argv[6]        # user1.bin or user2.bin
        user2_filename = sys.argv[7]        # user1.bin or user2.bin
        print(("genbin.py: create %s and %s from %s") %
              (user1_filename, user2_filename, elf_filename))
        gen_appbin (1, flash_mode, flash_clk_div, flash_size_map, user1_filename)
        gen_appbin (2, flash_mode, flash_clk_div, flash_size_map, user2_filename)
    
    close_elf()

if __name__=='__main__':
    main()