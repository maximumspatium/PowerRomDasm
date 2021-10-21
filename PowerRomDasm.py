'''
    Power Macintosh ROM disassembler.

    Author: Max Poliakovski 2020-2021

    Usage:
    python3 PowerRomDasm.py --rom_path=[path to a Power Macintosh ROM dump]
'''
from argparse import ArgumentParser
from ruamel.yaml import YAML

from capstone import *
from capstone.m68k import *

import struct

def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n

def align(n, m):
    return (n + m - 1) & bit_not(m - 1)

''' Capstone-based disassembler for 68k code.'''
class M68KDasm:
    def __init__(self, cb):
        self.rom_cb = cb
        self.cse = Cs(CS_ARCH_M68K, CS_MODE_M68K_040)
        self.cse.detail = True
        self.labels = {}

    def dasm_single(self, address, code):
        ''' Disassble single 68k instruction with the Capstone engine. '''

        # detect A-Traps and disassemble them ourselves
        if (code[0] & 0xF0) == 0xA0:
            from mactraps import TRAP_TABLE

            trap_num = (code[0] << 8) | code[1]
            if trap_num in TRAP_TABLE:
                return ((TRAP_TABLE[trap_num], [], 2))
            else:
                return (('dc.w', [hex(trap_num)], 2))

        # disassemble non-trap instructions with Capstone
        instrs = self.cse.disasm(code, address)
        return next(instrs)

    def dasm_region(self, addr, size, data):
        pp_dasm = []
        last_addr = addr + size
        offset = 0

        while addr < last_addr:
            # prefetch binary data (2 >= bytes <= 10) for the next instruction
            bin_length = min(last_addr - addr, 10)
            bin_prefetch = bytearray()
            for i in range(bin_length):
                bin_prefetch.append(data[offset+i])

            instr = self.dasm_single(addr, bin_prefetch)

            if not isinstance(instr, CsInsn):
                pp_dasm.append({'addr': addr, 'mnem': instr[0], 'ops': instr[1]})
                addr += instr[2]
                offset += instr[2]
                continue

            op_list = instr.op_str.split(',')
            #print(op_list)
            ops = []
            for op in instr.operands:
                #print(op.type)
                if op.type == M68K_OP_MEM:
                    #print(op.address_mode)
                    if op.address_mode == M68K_AM_PCI_DISP:
                        ea = addr + op.mem.disp + 2
                        flag,sym = self.rom_cb.get_symbol(ea)
                        if flag:
                            ops.append(sym)
                        else:
                            label = 'l_{:x}'.format(ea)
                            ops.append(label)
                            if ea not in self.labels:
                                self.labels[ea] = label
                        # discard current op because we've just replaced it
                        op_list.pop(0)
                    elif op.address_mode == M68K_AM_PCI_INDEX_BASE_DISP:
                        ops.append(instr.op_str)
                    else:
                        ops.append(op_list.pop(0))
                elif op.type == M68K_OP_BR_DISP:
                    if op.address_mode == M68K_AM_BRANCH_DISPLACEMENT:
                        ea = addr + op.br_disp.disp + 2
                        flag,sym = self.rom_cb.get_symbol(ea)
                        if flag:
                            ops.append(sym)
                        else:
                            label = 'l_{:x}'.format(ea)
                            ops.append(label)
                            if ea not in self.labels:
                                self.labels[ea] = label
                        # discard current op because we've just replaced it
                        op_list.pop(0)
                    else:
                        ops.append(op_list.pop(0))
                else:
                    ops.append(op_list.pop(0))
            pp_dasm.append({'addr': addr, 'mnem': instr.mnemonic, 'ops': ops})
            addr += instr.size
            offset += instr.size
            #print(ops)
            #print(self.labels)
        for instr in pp_dasm:
            if instr['addr'] in self.labels:
                print('\n' + self.labels[instr['addr']] + ':')
            print(hex(instr['addr']).ljust(15), end='')
            print(instr['mnem'], '\t', end='')
            print(','.join(instr['ops']))

    def dasm_regions(self, start_addr, size, data, regions):
        self.labels = {}
        for reg in regions:
            if reg[2] == 'align':
                print(hex(start_addr + reg[0]).ljust(15), end='')
                print('align\t' + str(reg[3]))
            elif reg[2] == 'code':
                reg_size = reg[1] - reg[0] + 1
                self.dasm_region(start_addr + reg[0], reg_size,
                    data[reg[3]:reg[3]+reg_size])
            else:
                print("Unknown region type " + reg[2])


class ROMDisassembler:
    def __init__(self, rom_data, rom_db):
        self.rom_data = rom_data
        self.rom_db = rom_db
        self.start_addr = rom_db['main_info']['phys_addr']
        self.m68k_dasm = M68KDasm(self)

    def get_symbol(self, addr):
        offset = addr - self.start_addr
        if offset in self.rom_db['annot_items']:
            return (True, self.rom_db['annot_items'][offset]['label'])
        else:
            return (False, '')

    def fmt_single_entry(self, format, size, offset):
        print(hex(self.start_addr + offset).ljust(15), end='')
        if format == 'hex':
            if size == 1:
                print("dc.b\t0x%X" % struct.unpack('>B', self.rom_data[offset:offset+1]))
            elif size == 2:
                print("dc.w\t0x%X" % struct.unpack('>H', self.rom_data[offset:offset+2]))
            elif size == 4:
                print("dc.l\t0x%X" % struct.unpack('>I', self.rom_data[offset:offset+4]))
            else:
                print("INVALID SIZE!")
        elif format == 'dec':
            if size == 1:
                print("dc.b\t%d" % struct.unpack('>B', self.rom_data[offset:offset+1]))
            elif size == 2:
                print("dc.w\t%d" % struct.unpack('>H', self.rom_data[offset:offset+2]))
            elif size == 4:
                print("dc.l\t%d" % struct.unpack('>I', self.rom_data[offset:offset+4]))
            else:
                print("INVALID SIZE!")
        elif format == 'offset':
            dest_offset = struct.unpack('>I', self.rom_data[offset:offset+4])[0]
            if dest_offset in self.rom_db['annot_items']:
                symbol = self.rom_db['annot_items'][dest_offset]['label']
                print("dc.l\t" + symbol + '-BaseOfRom')
            else:
                print("dc.l\t0x%X" % dest_offset)

    def parse_subregs(self, start, size, subregs):
        #print("This entry has subregions", subregs)
        regs = []
        reg_start = start
        for reg in subregs:
            if reg['type'] != 'align':
                print("Unknown subregion type " + reg['type'])
                return regs
            offset = reg['offset']
            if offset < reg_start or offset >= (start + size):
                print("Invalid subregion offset: 0x%X" % offset)
                return regs
            regs.append((reg_start, offset - 1, 'code', reg_start - start))
            boundary = reg['boundary']
            reg_end = align(offset, boundary)
            regs.append((offset, reg_end - 1, 'align', boundary))
            reg_start = reg_end
        if reg_start < (start + size):
            regs.append((reg_start, (start + size) - 1, 'code', reg_start - start))
        #print(regs)
        return regs


    def fmt_entry(self, entry, offset):
        print("")

        if entry['type'] == 'align':
            start = offset
            end   = align(start, entry['boundary'])
            print(hex(self.start_addr + start).ljust(15), end='')
            print('align\t' + str(entry['boundary']))
            return end - start

        print((entry['label'] + ':').ljust(15))

        if entry['type'] == 'array':
            count = entry['size'] // entry['elsize']
            for i in range(count):
                self.fmt_single_entry(entry['format'], entry['elsize'], offset)
                offset += entry['elsize']
        elif entry['type'] == 'int':
            self.fmt_single_entry(entry['format'], entry['size'], offset)
        elif entry['type'] == 'code':
            size = entry['size']
            if entry['arch'] == '68k':
                if 'subregs' in entry:
                    regs = self.parse_subregs(offset, size, entry['subregs'])
                else:
                    regs = [(offset, offset + size - 1, 'code', 0)]
                self.m68k_dasm.dasm_regions(self.start_addr, size,
                    self.rom_data[offset:offset+size], regs)
            elif entry['arch'] == 'ppc':
                print("PPC disassembler not implemented yet")
            else:
                print("Unknown code region architecture " + entry['arch'])
        elif entry['type'] == 'fixlenstr': # fixed-length string
            print(hex(self.start_addr + offset).ljust(15), end='')
            str_len = entry['size']
            fmt_str = '%is' % str_len
            print('"%s"' % struct.unpack(fmt_str, self.rom_data[offset:offset+str_len])[0].decode('mac_roman'))

        return entry['size']

    def dasm_region(self, start, end):
        offset = start
        while offset < end:
            if offset in self.rom_db['annot_items']:
                entry = self.rom_db['annot_items'][offset]
                size = self.fmt_entry(entry, offset)
                offset += size
            else:
                print(hex(self.start_addr + offset).ljust(15), end='')
                print("dc.b\t0x%X" % struct.unpack('>B', self.rom_data[offset:offset+1]))
                offset += 1


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--rom_path', type=str,
                        dest='rom_path',
                        help='path to a PowerMacintosh ROM file to process',
                        metavar='ROM_PATH', required=True)
    parser.add_argument('--start', type=lambda x: int(x,0),
                        dest='start_offs', default=0,
                        help='offset to the start of the region to disassemble',
                        required=False,
                        )
    parser.add_argument('--end', type=lambda x: int(x,0),
                        dest='end_offs', default=0x500,
                        help='offset to the end of the region to disassemble',
                        required=False,
                        )

    opts = parser.parse_args()

    with open(opts.rom_path, 'rb') as rom_file:
        rom_file.seek(0, 2)
        rom_size = rom_file.tell()
        if rom_size != (4 * 1024 * 1024):
            print("Invalid ROM file size %d (expected 4 MB)" % rom_size)

        # just load the whole ROM image into memory
        rom_file.seek(0, 0)
        rom_data = rom_file.read()

        check_sum = struct.unpack('>I', rom_data[0:4])[0]
        print("ROM Checksum: %X" % check_sum)

        db_name = 'ROMDB_' + '{:x}'.format(int(check_sum)).upper() + '.yaml'

        with open('database/' + db_name, 'rb') as db_file:
            yaml = YAML()
            annot_db = yaml.load(db_file)

            print(annot_db['main_info']['name'])

            rdasm = ROMDisassembler(rom_data, annot_db)
            rdasm.dasm_region(opts.start_offs, opts.end_offs)
