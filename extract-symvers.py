#!/usr/bin/env python

import gzip
import struct
import sys
import io
import zlib
from optparse import OptionParser
import importlib

lzmaPresent = False
try:
    if importlib.import_module('lzma'):
        import lzma
        lzmaPresent = True
except ImportError:
    pass

zstdPresent = False
try:
    if importlib.import_module('zstandard'):
        import zstandard
        zstdPresent = True
except ImportError:
    pass

ENDIANNESS = {
  'little': '<',
  'le': '<',
  'big': '>',
  'be': '>'
}

PTR = {
  32: 'L',
  64: 'Q'
}

EXPORT_TYPE = [
  'EXPORT_SYMBOL',
  'EXPORT_SYMBOL_GPL',
  'EXPORT_SYMBOL_GPL_FUTURE'
]

UBOOT_COMP = [ 'none', 'gzip', 'bzip2', 'lzma', 'lzo', 'lz4', 'zstd', 'unknown' ]
UBOOT_ARCH = [
 'invalid', 'alpha', 'arm', 'i386', 'ia64', 'mips', 'mips64', 'ppc', 's390', 'sh',
 'sparc', 'sparc64', 'm68k', 'nios', 'microblaze', 'nios2', 'blackfin', 'avr32',
 'st200', 'sandbox', 'nds32', 'openrisc', 'arm64', 'arc', 'x86_64', 'xtensa', 'riscv'
]

class KernelImage(object):
    def __init__(self, file, base, endian, ptr_size, kver, prel32):
        self.base = base
        self.ptr_format = ENDIANNESS[endian] + PTR[ptr_size]
        self.endian = ENDIANNESS[endian]
        self.ptr = PTR[ptr_size]
        self.ptr_bytes = ptr_size >> 3
        self.kver = kver
        self.prel32 = prel32
        with open(file, 'rb') as f:
            self.kernel = f.read()
        self.decompress_kernel()

    def unpack_gzip(self, index):
        sys.stderr.write( "gzip compressed at pos " + str(index) + " (" + hex(index) + ")\n")
        self.kernel = zlib.decompress(self.kernel[index:], zlib.MAX_WBITS|16)

    def unpack_lzma(self, index):
        sys.stderr.write( "lzma compressed at pos " + str(index) + " (" + hex(index) + ")\n")
        if not lzmaPresent:
            sys.stderr.write("lzma python module is not available. Pls unpack vmlinuz manually or update python.\n")
            exit(5)
        self.kernel = lzma.LZMADecompressor().decompress(self.kernel[index:])

    def unpack_zstd(self, index):
        sys.stderr.write( "zstd compressed at pos " + str(index) + " (" + hex(index) + ")\n")
        if not zstdPresent:
            sys.stderr.write("zstandard python module is not available. Pls unpack vmlinuz manually or `pip install zstandard`.\n")
            exit(5)
        self.kernel = zstandard.decompress(self.kernel[index:],max_output_size=128*1024*1024)

    def unpack_lz4(self, index):
        sys.stderr.write( "lz4 compressed at pos " + str(index) + " (" + hex(index) + ")\n")
        sys.stderr.write( "lz4 (legacy) compression is not supported. Pls unpack vmlinuz manually.\n")
        exit(5)

    def find_unpack(self, magic, unpacker):
        index = self.head.find(magic, self.start_index)
        if index != -1:
            self.start_index = index
            unpacker(index)
            return True
        return False

    def decompress_kernel(self):
        # u-boot header
        if self.kernel[0:4].find(b'\x27\x05\x19\x56')==0:
            sys.stderr.write( "u-boot image header found. header size is 64 bytes.\n")
            comp_raw = struct.unpack('B', self.kernel[0x1f:0x20])[0]
            comp = comp_raw
            if comp>=(len(UBOOT_COMP)-1):
                comp=len(UBOOT_COMP)-1
            arch_raw = struct.unpack('B', self.kernel[0x1d:0x1e])[0]
            arch = arch_raw if arch_raw<len(UBOOT_ARCH) else 0
            imgtype = struct.unpack('B', self.kernel[0x1e:0x1f])[0]
            load = struct.unpack('>I', self.kernel[0x10:0x14])[0]
            entry = struct.unpack('>I', self.kernel[0x14:0x18])[0]
            sys.stderr.write( "compression " + str(comp_raw) + " (" + UBOOT_COMP[comp] + ") arch " + \
                str(arch_raw) + " (" + UBOOT_ARCH[arch_raw] + ") type " + str(imgtype) + " load_address " + \
                hex(load) + " entry_point " + hex(entry) + "\n" )
            sys.stderr.write(self.read_str(0x20) + "\n" )
            if imgtype!=2:
                sys.stderr.write( "image type tells this is not a linux kernel\n" )
                exit(6)
            if comp==1:
                self.unpack_gzip(64)
            elif comp==3:
                self.unpack_lzma(64)
            elif comp==5:
                self.unpack_lz4(64)
            elif comp==6:
                self.unpack_zstd(64)
            elif comp!=0:
                sys.stderr.write( "unsupported compression type " + str(comp_raw) + "\n")
                exit(5)
            if comp!=0:
                self.size = len(self.kernel)
                return
            # fall through because payload can be vmlinuz

        self.size = len(self.kernel)
        head_size = self.size if self.size<0x18000 else 0x18000
        self.head = self.kernel[0:head_size]
        unpackers = [
            [ 'gzip' , b'\x1f\x8b\x08', self.unpack_gzip ],
            [ 'lzma', b'\xfd\x37\x7a\x58\x5a\x00', self.unpack_lzma],
            [ 'zstd', b'\x28\xb5\x2f\xfd', self.unpack_zstd],
            [ 'lz4', b'\x02\x21\x4c\x18', self.unpack_lz4]
        ]
        compressed = False
        for unpacker in unpackers :
            sys.stderr.write( "searching for " + unpacker[0] + "\n" )
            self.start_index = 0
            while self.start_index >= 0 and self.start_index < len(self.head) :
                try:
                    if self.find_unpack(unpacker[1], unpacker[2]) : compressed = True
                    break
                except SystemExit:
                    raise
                except:
                    sys.stderr.write( "decompression failed\n" )
                    self.start_index = self.start_index + 3
            if compressed: break
        if not compressed: sys.stderr.write( "not compressed or unsupported compression\n" )
        self.size = len(self.kernel)

    def read_ptr(self, offset):
        return struct.unpack(self.endian + self.ptr, self.kernel[offset:offset + self.ptr_bytes])[0]

    def read_uint(self, offset):
        return struct.unpack(self.endian + 'I', self.kernel[offset:offset + 4])[0]

    def read_u64(self, offset):
        return struct.unpack(self.endian + 'Q', self.kernel[offset:offset + 8])[0]

    def is_valid_ptr(self, ptr):
        offset = ptr - self.base
        return offset >= 0 and offset < self.size

    def read_str(self, offset):
        return self.kernel[offset:self.kernel.index(b'\0',offset)].decode('ascii')

    def scan_symsearch(self):
        offset = 0
        symsearch_5_12 = self.kver>=0x50C
        # 5.12-
        # size 20 if 32 bit, 32 if 64 bit (8 byte ptr aligntment)
        #struct symsearch {
        #  const struct kernel_symbol *start, *stop;
        #  const s32 *crcs;
	#  enum mod_license {
	#    NOT_GPL_ONLY,
	#    GPL_ONLY,
	#    WILL_BE_GPL_ONLY,
	#  } license;
	#  bool unused;
        #};        
        # 5.12+
        # size 16 if 32 bit, 32 if 64 bit (8 byte ptr aligntment)
        #struct symsearch {
	#  const struct kernel_symbol *start, *stop;
        #  const s32 *crcs;
        #  enum mod_license {
	#    NOT_GPL_ONLY,
	#    GPL_ONLY,
	# } license;
        #};
        struct_size = 3*self.ptr_bytes + (4 if symsearch_5_12 and self.ptr_bytes==4 else 8)
        licenses = [0, 1] if symsearch_5_12 else [0, 1, 2]
        symsearch = {}
        while (offset + 3*struct_size) <= self.size:
            symtab = [offset + 3*self.ptr_bytes, offset + struct_size + 3*self.ptr_bytes, offset + 2*struct_size + 3*self.ptr_bytes]
            # license NOT_GPL_ONLY, GPL_ONLY, WILL_BE_GPL_ONLY
            # kernel 5.12- : unused=0
            if symsearch_5_12 and (self.read_uint(symtab[0])==0 and self.read_uint(symtab[1])==1) \
               or not symsearch_5_12 and \
                  (self.read_uint(symtab[0])==0 and self.read_uint(symtab[0]+4)==0 and
                   self.read_uint(symtab[1])==1 and self.read_uint(symtab[1]+4)==0 and
                   self.read_uint(symtab[2])==2 and self.read_uint(symtab[2]+4)==0) :
                off = offset
                ptrs = {}
                ptrs_ok = True
                for i in licenses:
                    ptrs[i] = {}
                    ptrs[i]['start'] = self.read_ptr(off)
                    ptrs[i]['stop'] = self.read_ptr(off + self.ptr_bytes)
                    ptrs[i]['crcs'] = self.read_ptr(off + 2*self.ptr_bytes)
                    for ptr in ptrs[i] :
                        if not self.is_valid_ptr(ptrs[i][ptr]) :
                            ptrs_ok = False
                            break
                    off += struct_size
                if ptrs_ok:
                    sys.stderr.write("symsearch found at offset " + hex(offset) + "\n")
                    for i in licenses:
                        sys.stderr.write("catalog " + EXPORT_TYPE[i] + " : " + hex(ptrs[i]['start'] - self.base) + "-" + hex(ptrs[i]['stop'] - self.base) + " crcs " + hex(ptrs[i]['crcs'] - self.base) + "\n")
                        symsearch[EXPORT_TYPE[i]] = ptrs[i]
                    return symsearch
            offset += self.ptr_bytes

    def symbols(self):
        symsearch = self.scan_symsearch()
        if not symsearch:
            sys.stderr.write("symsearch not found\n")
            return
        ksym_members = 3 if self.kver>=0x504 else 2
        # 4.10-
        #  unsigned long *
        # 4.10+
        #  s32 *
        crc_size = 4 if self.kver>=0x40A else self.ptr_bytes
        for t, s in symsearch.items():
            crc_off = s['crcs'] - self.base
            if self.prel32:
                # 5.4-
                #struct kernel_symbol {
                #  int value_offset;
                #  int name_offset;
                #};
                # 5.4+
                #struct kernel_symbol {
                #  int value_offset;
                #  int name_offset;
                #  int namespace_offset;
                #};
                for offset in range(s['start'] - self.base, s['stop'] - self.base, 4 * ksym_members):
                    name_offset = offset + 4 + self.read_uint(offset + 4)
                    if name_offset >= self.size :
                        sys.stderr.write("name_offset " + str(name_offset) + " (" + hex(name_offset) + ") is outside of the file\n")
                        return
                    crc = self.read_uint(crc_off) if crc_size==4 else self.read_u64(crc_off)
                    yield self.read_str(name_offset), crc, t
                    crc_off += crc_size
            else :
                # 5.4-
                #struct kernel_symbol {
                #  unsigned long value;
                #  const char *name;
                #};
                # 5.4+
                #struct kernel_symbol {
                #  unsigned long value;
                #  const char *name;
                #  const char *namespace;
                #};
                for offset in range(s['start'] - self.base, s['stop'] - self.base, self.ptr_bytes * ksym_members):
                    name_ptr = self.read_ptr(offset + self.ptr_bytes)
                    if not self.is_valid_ptr(name_ptr) :
                        sys.stderr.write("name_ptr " + hex(name_ptr) + " is outside of the file\n")
                        return
                    crc = self.read_uint(crc_off) if crc_size==4 else self.read_u64(crc_off)
                    yield self.read_str(name_ptr - self.base), crc, t
                    crc_off += crc_size

def main():
    parser = OptionParser()
    parser.add_option('-B', '--base-address', dest='base', metavar='ADDRESS',
        help='Base address (in hex) where the kernel is loaded [required]')
    parser.add_option('-e', '--endian', dest='endian', metavar='ENDIANNESS',
        choices=['big', 'little', 'be', 'le'], default='little',
        help='Endianness (big|little|be|le) ; defaults to little/le')
    parser.add_option('-b', '--bits', dest='bits', metavar='ADDRESS',
        choices=['32', '64'], default='32',
        help='Size of pointers in bits ; defaults to 32')
    parser.add_option('-k', '--kernel-version', dest='kver', metavar='KVER',
        default='old', help='Kernel version : major.minor')
    parser.add_option('-p', '--prel32', dest='prel32', metavar='PREL32',
        choices=['y', 'n'], default='y',
        help='For kernels 4.19+ : CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=[y,n]')
    parser.add_option('-d', '--decompress', dest='decompress', metavar='FILE',
        help='Decompress the kernel to a file')


    (options, args) = parser.parse_args()
    if not options.base and not options.decompress:
        sys.stderr.write("Missing option: -B/--base-address or -d/--decompress\n")
        exit(1)

    if len(args) != 1:
        sys.stderr.write("Need exactly one kernel file\n")
        exit(1)

    if options.kver=='old':
        kver = 0x206
    else:
        try:
            m = options.kver.replace('+','').split('.')
            kver = (int(m[0])<<8) + int(m[1])
        except:
            sys.stderr.write("invalid kernel version : " + options.kver + "\n")
            exit(1)
    sys.stderr.write("kernel version " + str(kver>>8) + "." + str(kver & 0xFF) + " " + options.bits + "-bit " + options.endian + " endian\n")

    kernel = KernelImage(args[0], 0 if options.decompress else int(options.base, 16), options.endian, int(options.bits), kver, kver>=0x413 and options.prel32=='y')

    if options.decompress:
        sys.stderr.write("saving unpacked kernel to " + options.decompress + "\n")
        with open(options.decompress, 'wb') as f:
            f.write(kernel.kernel)
    else:
        for s, crc, t in kernel.symbols():
            print ("0x%08x\t%s\tvmlinux\t%s" % (crc, s, t))

if __name__ == '__main__':
    main()
