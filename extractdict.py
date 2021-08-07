'''
    Dictionary extraction script for Apple OpenFirmware.

    Author: Max Poliakovski 2019-2021
'''
import os
import struct
from argparse import ArgumentParser

class OFWordHeader:
    def __init__(self, infile, pos):
        infile.seek(pos)

        # get common fields
        hdr = struct.unpack('>iBBH', infile.read(8))
        self.prev    = hdr[0]
        self.flags   = hdr[1]
        self.type    = hdr[2]
        self.tok_num = hdr[3]

        if self.flags & 0x20: # bit 5 means nameless word
            # generate artificial name
            self.name = 'unnamed_' + format(self.tok_num, 'x')
        else:
            len = struct.unpack('B', infile.read(1))[0]
            self.name = struct.unpack('%ds' % len,
                        infile.read(len))[0].decode('utf-8')

        self.pos = pos


def parse_coff_container(infile, cont_offset):
    infile.seek(cont_offset)

    # read COFF header
    coff_hdr = struct.unpack('>HHL', infile.read(8))
    n_sections = coff_hdr[1]

    # COFF magic and at least one section are required
    if coff_hdr[0] != 0x1DF or n_sections < 1:
        print("No valid COFF header found at offset %X" % cont_offset)
        return (0, 0)

    if coff_hdr[2] == 0x47617279:
        print("Detected Macintosh OldWorld OF binary...")

    infile.seek(cont_offset + 20) # rewind to sections array

    # search for executable code section
    for sect in range(n_sections):
        sect_desc = struct.unpack('>8sLLLLLLHHL', infile.read(40))
        sect_name = sect_desc[0].decode('utf-8').strip('\x00')
        if sect_name == '.text':
            return (sect_desc[4], sect_desc[3])

    return (0, 0)


def scan_forth_dict(infile, pos, end_pos):
    # try offset at code_section[0x48] that usually points
    # to the header of the last word (cold-load)
    infile.seek(pos + 0x48)
    dict_last_offset = struct.unpack('>L', infile.read(4))[0]
    if (dict_last_offset + 20) >= end_pos:
        return 0

    word = OFWordHeader(infile, dict_last_offset + pos)
    if word.name == 'cold-load':
        print("cold-load found at offset %X" % word.pos)
    else:
        print('Scanning for cold-load not implemented yet')
        return 0

    print('\n')

    forth_dict = {}

    word_pos = dict_last_offset + pos

    while 1:
        forth_dict[word.tok_num] = {'name' : word.name, 'type' : word.type, 'pos' : word.pos}
        if word.prev >= 0:
            return forth_dict
        word_pos += word.prev
        del word
        word = OFWordHeader(infile, word_pos)


def print_dict(dict):
    for tok_num, word in dict.items():
        print("Word: %04X, name: %s, type: %02X, offset = %08X" % (tok_num, word['name'], word['type'], word['pos']))


def main():
    parser = ArgumentParser()
    parser.add_argument('--rom_path', type=str,
                        dest='rom_path',
                        help='path to ROM file to process',
                        metavar='ROM_PATH', required=True)
    parser.add_argument('--offset', type=lambda x: int(x,0),
                        dest='of_offset',
                        help='offset to OF container (autodetect attempt if omitted)',
                        metavar='OF_OFFSET', required=True)
    opts = parser.parse_args()

    with open(opts.rom_path, 'rb') as infile:
        pos, size = parse_coff_container(infile, opts.of_offset);
        if size == 0:
            print("No valid OF binary found at offset %X" % opts.of_offset)
            exit(1)

        dict = scan_forth_dict(infile, opts.of_offset + pos, pos + size)

        print_dict(dict)


if __name__ == '__main__':
    main()
