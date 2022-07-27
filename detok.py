'''
    FCode DeTokenizer in pure Python.

    Author: Max Poliakovski 2019-2021
'''
import struct

FORTH_WORDS = {
    0x10  : ('b(lit)',       ['num32']),
    0x11  : ("b(')",         ['fcode_num']),
    0x12  : ('b(")',         ['p_string']),
    0x13  : ('bbranch',      ['offset']),
    0x14  : ('b?branch',     ['offset']),
    0x15  : ('b(loop)',      ['offset']),
    0x16  : ('b(+loop)',     ['offset']),
    0x17  : ('b(do)',        ['offset']),
    0x18  : ('b(?do)',       ['offset']),
    0x19  : ('i',            []),
    0x1A  : ('j',            []),
    0x1B  : ('b(leave)',     []),
    0x1C  : ('b(of)',        ['offset']),
    0x1D  : ('execute',      []),
    0x1E  : ('+',            []),
    0x1F  : ('-',            []),
    0x20  : ('*',            []),
    0x21  : ('/',            []),
    0x22  : ('mod',          []),
    0x23  : ('and',          []),
    0x24  : ('or',           []),
    0x25  : ('xor',          []),
    0x26  : ('invert',       []),
    0x27  : ('lshift',       []),
    0x28  : ('rshift',       []),
    0x29  : ('>>a',          []),
    0x2A  : ('/mod',         []),
    0x2B  : ('u/mod',        []),
    0x2C  : ('negate',       []),
    0x2D  : ('abs',          []),
    0x2E  : ('min',          []),
    0x2F  : ('max',          []),
    0x30  : ('>r',           []),
    0x31  : ('r>',           []),
    0x32  : ('r@',           []),
    0x33  : ('exit',         []),
    0x34  : ('0=',           []),
    0x35  : ('0<>',          []),
    0x36  : ('0<',           []),
    0x37  : ('0<=',          []),
    0x38  : ('0>',           []),
    0x39  : ('0>=',          []),
    0x3A  : ('<',            []),
    0x3B  : ('>',            []),
    0x3C  : ('=',            []),
    0x3D  : ('<>',           []),
    0x3E  : ('u>',           []),
    0x3F  : ('u<=',          []),
    0x40  : ('u<',           []),
    0x41  : ('u>=',          []),
    0x42  : ('>=',           []),
    0x43  : ('<=',           []),
    0x44  : ('between',      []),
    0x45  : ('within',       []),
    0x46  : ('drop',         []),
    0x47  : ('dup',          []),
    0x48  : ('over',         []),
    0x49  : ('swap',         []),
    0x4A  : ('rot',          []),
    0x4B  : ('-rot',         []),
    0x4C  : ('tuck',         []),
    0x4D  : ('nip',          []),
    0x4E  : ('pick',         []),
    0x4F  : ('roll',         []),
    0x50  : ('?dup',         []),
    0x51  : ('depth',        []),
    0x52  : ('2drop',        []),
    0x53  : ('2dup',         []),
    0x54  : ('2over',        []),
    0x55  : ('2swap',        []),
    0x57  : ('2/',           []),
    0x59  : ('2*',           []),
    0x5C  : ('/l',           []),
    0x5E  : ('ca+',          []),
    0x5F  : ('wa+',          []),
    0x60  : ('la+',          []),
    0x61  : ('na+',          []),
    0x62  : ('char+',        []),
    0x63  : ('wa1+',         []),
    0x64  : ('la1+',         []),
    0x65  : ('cell+',        []),
    0x68  : ('/l*',          []),
    0x69  : ('cells',        []),
    0x6A  : ('on',           []),
    0x6B  : ('off',          []),
    0x6C  : ('+!',           []),
    0x6D  : ('@',            []),
    0x6E  : ('l@',           []),
    0x6F  : ('w@',           []),
    0x71  : ('c@',           []),
    0x72  : ('!',            []),
    0x73  : ('l!',           []),
    0x74  : ('w!',           []),
    0x75  : ('c!',           []),
    0x76  : ('2@',           []),
    0x77  : ('2!',           []),
    0x78  : ('move',         []),
    0x79  : ('fill',         []),
    0x7A  : ('comp',         []),
    0x7C  : ('lwsplit',      []),
    0x7D  : ('wljoin',       []),
    0x7E  : ('lbsplit',      []),
    0x7F  : ('bljoin',       []),
    0x80  : ('wbflip',       []),
    0x83  : ('pack',         []),
    0x84  : ('count',        []),
    0x85  : ('body>',        []),
    0x86  : ('>body',        []),
    0x89  : ('unloop',       []),
    0x8B  : ('alloc-mem',    []),
    0x8C  : ('free-mem',     []),
    0x8D  : ('key?',         []),
    0x8E  : ('key',          []),
    0x90  : ('type',         []),
    0x92  : ('cr',           []),
    0x9D  : ('.',            []),
    0xA0  : ('base',         []),
    0xA4  : ('-1',           []),
    0xA5  : ('0',            []),
    0xA6  : ('1',            []),
    0xA7  : ('2',            []),
    0xA8  : ('3',            []),
    0xA9  : ('bl',           []),
    0xAA  : ('bs',           []),
    0xAB  : ('bell',         []),
    0xAC  : ('bounds',       []),
    0xAD  : ('here',         []),
    0xAE  : ('aligned',      []),
    0xAF  : ('wbsplit',      []),
    0xB0  : ('bwjoin',       []),
    0xB1  : ('b(<mark)',     []),
    0xB2  : ('b(>resolve)',  []),
    0xB5  : ('new-token',    ['unnamed_tok']),
    0xB7  : ('b(:)',         []),
    0xB8  : ('b(value)',     ['line_break']),
    0xB9  : ('b(variable)',  ['line_break']),
    0xBA  : ('b(constant)',  ['line_break']),
    0xBB  : ('b(create)',    ['line_break']),
    0xBC  : ('b(defer)',     ['line_break']),
    0xBD  : ('b(buffer:)',   ['line_break']),
    0xBE  : ('b(field)',     ['line_break']),
    0xC0  : ('instance',     []),
    0xC2  : ('b(;)',         ['line_break']),
    0xC3  : ('b(to)',        ['fcode_num']),
    0xC4  : ('b(case)',      []),
    0xC5  : ('b(endcase)',   []),
    0xC6  : ('b(endof)',     ['offset']),
    0xCA  : ('external-token', ['named_tok']),
    0xD0  : ('c,',           []),
    0xD1  : ('w,',           []),
    0xD2  : ('l,',           []),
    0xD3  : (',',            []),
    0xD4  : ('um*',          []),
    0xD5  : ('um/mod',       []),
    0xD8  : ('d+',           []),
    0xD9  : ('d-',           []),
    0xDA  : ('get-token',    []),
    0xDB  : ('set-token',    []),
    0xDC  : ('state',        []),
    0xF1  : ('start1',       ['fcode_hdr', 'offset16']),
    0xFD  : ('version1',     ['fcode_hdr', 'offset8']),
    0x102 : ('my-address',   []),
    0x103 : ('my-space',     []),
    0x104 : ('memmap',       []),
    0x110 : ('property',     []),
    0x111 : ('encode-int',   []),
    0x112 : ('encode+',      []),
    0x113 : ('encode-phys',  []),
    0x114 : ('encode-string', []),
    0x115 : ('encode-bytes', []),
    0x119 : ('model',        []),
    0x11A : ('device-type',  []),
    0x11C : ('is-install',   []),
    0x11D : ('is-remove',    []),
    0x11F : ('new-device',   []),
    0x125 : ('get-msecs',    []),
    0x126 : ('ms',           []),
    0x128 : ('decode-phys',  []),
    0x150 : ('#lines',       []),
    0x15A : ('erase-screen', []),
    0x166 : ('window-left',  []),
    0x16A : ('default-font', []),
    0x16B : ('set-font',     []),
    0x16C : ('char-height',  []),
    0x16D : ('char-width',   []),
    0x18B : ('fb8-install',  []),
    0x201 : ('device-name',  []),
    0x203 : ('my-self',      []),
    0x204 : ('find-package', []),
    0x207 : ('find-method',  []),
    0x209 : ('$call-parent', []),
    0x20A : ('my-parent',    []),
    0x20B : ('ihandle>phandle', []),
    0x20F : ('$open-package', []),
    0x216 : ('abort',        []),
    0x21A : ('get-my-property', []),
    0x21B : ('decode-int',   []),
    0x21D : ('get-inherited-property', []),
    0x21E : ('delete-property', []),
    0x226 : ('lwflip',       []),
    0x227 : ('lbflip',       []),
    0x230 : ('rb@',          []),
    0x231 : ('rb!',          []),
    0x232 : ('rw@',          []),
    0x233 : ('rw!',          []),
    0x234 : ('rl@',          []),
    0x235 : ('rl!',          [])
}

class DeTokenizer():
    def __init__(self, code_stream, code_len, pos = 0):
        self.pos = pos
        self.code_stream = code_stream
        self.code_length = code_len
        self.offset_bits = 8
        self.builtin_dict = FORTH_WORDS
        self.user_dict = {}
        self.new_line = False

    def reinit(self, code_stream, code_len, pos = 0):
        self.pos = pos
        self.code_stream = code_stream
        self.code_length = code_len
        self.offset_bits = 8
        self.new_line = False

    def next_toknum(self):
        tok_num = self.code_stream[self.pos]
        self.pos += 1
        if tok_num > 0 and tok_num <= 0xF:
            tok_num = (tok_num << 8) | self.code_stream[self.pos]
            self.pos += 1
        return tok_num

    def fcode_hdr(self):
        fcode_hdr = struct.unpack('>BHL', self.code_stream[self.pos:self.pos+7])
        self.pos += 7
        print("FCode header:")
        print("- format   = 0x%X" % fcode_hdr[0])
        print("- checksum = 0x%X" % fcode_hdr[1])
        print("- prog_len = 0x%X\n" % fcode_hdr[2])

    def offset8(self):
        self.offset_bits = 8

    def offset16(self):
        self.offset_bits = 16

    def offset(self):
        if self.offset_bits == 8:
            val = self.code_stream[self.pos]
            self.pos += 1
        elif self.offset_bits == 16:
            val = (self.code_stream[self.pos] << 8) | (self.code_stream[self.pos+1])
            self.pos += 2
        sign = 1 << (self.offset_bits - 1)
        offset = (val & (sign - 1)) - (val & sign)
        print("- offset: %d" % offset)

    def num32(self):
        num = (self.code_stream[self.pos] << 24)   | \
              (self.code_stream[self.pos+1] << 16) | \
              (self.code_stream[self.pos+2] << 8)  | \
               self.code_stream[self.pos+3]
        self.pos += 4
        print("- number: 0x%X" % num)

    def fcode_num(self):
        num = self.next_toknum()
        print("- FCode #: 0x%X" % num)
        return num

    def unnamed_tok(self):
        tok_num = self.fcode_num()
        tok_name = 'unnamed_' + format(tok_num, 'x')
        #if tok_num not in self.user_dict:
        self.user_dict[tok_num] = tok_name

    def named_tok(self):
        tok_name = self.p_string()
        tok_num = self.fcode_num()
        #if tok_num not in self.user_dict:
        self.user_dict[tok_num] = tok_name

    def p_string(self):
        len = self.code_stream[self.pos]
        self.pos += 1
        try:
            str = struct.unpack('%ds' % len, \
                  self.code_stream[self.pos:self.pos+len])[0].decode('utf-8')
            self.pos += len
            print('- String: " %s"' % str)
            return str
        except UnicodeDecodeError: # Forth string may contain non-printable chars!
            bytes = struct.unpack('%dB' % len, \
                    self.code_stream[self.pos:self.pos+len])
            self.pos += len
            print(' '.join(format(x, '02x') for x in bytes))
            return bytes

    def line_break(self):
            print("")
            self.new_line = True

    def insert_newline(self, tok_num):
        if tok_num == 0xCA or tok_num == 0xB5:
            if not self.new_line:
                self.line_break()
        else:
            self.new_line = False

    def decode_stream(self):
        while self.pos < self.code_length:
            tok_num = self.next_toknum()
            if tok_num == 0:
                print('0x00 ; end0')
                break

            self.insert_newline(tok_num)

            if tok_num in self.builtin_dict:
                dict_entry = self.builtin_dict[tok_num]
                print("0x%X ; %s" % (tok_num, dict_entry[0]))
                for fun in dict_entry[1]:
                    fun_obj = getattr(self, fun)
                    fun_obj()
            elif tok_num in self.user_dict: # check user dictionary
                print("0x%X ; %s" % (tok_num, self.user_dict[tok_num]))
            else:
                print("0x%X ; %s" % (tok_num, 'undefined_' + format(tok_num, 'x')))
