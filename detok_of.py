'''
    DeTokenizer for Apple OpenFirmware.

    Author: Max Poliakovski 2019-2021
'''
import struct
from argparse import ArgumentParser

from extractdict import parse_coff_container, scan_forth_dict, print_dict

from detok import DeTokenizer

def get_fcode_prog(infile):
    # try to get FCode program header
    fpos = infile.tell()
    fcode_hdr = struct.unpack('>BBHL', infile.read(8))
    infile.seek(fpos)

    if fcode_hdr[0] != 0xFD and fcode_hdr[0] != 0xF1:
        #print("Unsupported FCode header function 0x%X" % fcode_hdr[0])
        return (0,0)
    prog_len = fcode_hdr[3]
    prog_stream = infile.read(prog_len)
    return (prog_stream, prog_len)


def decode_package_header(infile):
    pkg_hdr = struct.unpack('>LHHLL', infile.read(16))
    print("Device package header:")
    print("----------------------")
    print("Next package offset: %X" % pkg_hdr[0])
    print("Device ID: %X" % pkg_hdr[1])
    print("Vendor ID: %X" % pkg_hdr[2])
    print("Device class: %X" % pkg_hdr[3])
    print("Package header size: %X" % pkg_hdr[4])
    return (pkg_hdr[0], pkg_hdr[4])


def populate_user_dict(src_dict, dst_dict):
    for tok_num, word in src_dict.items():
        if tok_num >= 0x100:
            dst_dict[tok_num] = word['name']

    # add Apple specific FCodes for managing stack frames
    for i in range(0,9):
        dst_dict[0x407 + i] = '(pushlocals_%s)' % i

    for i in range(0,8):
        dst_dict[0x410 + i] = '(local@%s)' % i
        dst_dict[0x418 + i] = '(local!%s)' % i


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

        print("pos = 0x%X, size = 0x%X" % (pos, size))

        dict = scan_forth_dict(infile, opts.of_offset + pos, pos + size)

        #print_dict(dict)

        print("Detokenizing main OF package...")
        print("-------------------------------\n")

        infile.seek(opts.of_offset + pos + 8)
        prog_offset = struct.unpack('>L', infile.read(4))[0]
        print("FCode program offset: %X" % (prog_offset + pos))

        infile.seek(opts.of_offset + prog_offset + pos)

        prog_stream, prog_size = get_fcode_prog(infile)

        detokenizer = DeTokenizer(prog_stream, prog_size)

        populate_user_dict(dict, detokenizer.user_dict)

        detokenizer.decode_stream()

        print("\nDetokenizing device packages...")
        print("-------------------------------\n")

        infile.seek(opts.of_offset + pos + 0x40)
        pkg_offset = struct.unpack('>L', infile.read(4))[0] + pos + opts.of_offset
        print("Last OF device package offset: %X" % (pkg_offset))

        prev_pkg_offset = pkg_offset

        while True:
            print("\n")
            infile.seek(pkg_offset)
            next_pkg_offset, hdr_size = decode_package_header(infile)

            prog_stream, prog_size = get_fcode_prog(infile)

            if prog_size == 0:
                prog_size = prev_pkg_offset - pkg_offset - hdr_size
                #print("Headerless FCode program size: %X" % prog_size)
                #print("File pos: %X" % infile.tell())
                prog_stream = infile.read(prog_size)

            print("\nDetokenizing package at offset %X...\n" % pkg_offset)

            detokenizer.reinit(prog_stream, prog_size)
            detokenizer.decode_stream()

            # navigate to previous package or exit if there is no more packages
            if next_pkg_offset == 0:
                break
            prev_pkg_offset = pkg_offset
            pkg_offset = (pkg_offset + next_pkg_offset) & 0xFFFFFFFF

if __name__ == '__main__':
    main()
