### Purpose

This python script allow to extract Module.symvers from a binary **vmlinux** or gzip/lzma/zstd compressed **vmlinuz** image in order to build modules without recompling the whole kernel.

### Determining kernel base address

Start your kernel with `nokaslr` command line option and analyze `/proc/kallsyms`. If all addresses are zeroes even if executed as **root** do `sysctl kernel.kptr_restrict=1` .

```
grep text /proc/kallsyms | head
```
If `text` starts not from page boundary (usually 0x1000 - 4096) then align it. For example, 0x80001400 => 0x80001000.

On android you can also look for address of kernel `.text` section in the beginning of dmesg. If kernel message buffer is too small try booting to **TWRP** recovery. Good chances you can see what you need.

Providing `nokaslr` as command line argument to android kernel is possible but not very easy. You must unpack boot image, extract device tree (dtb) from there, decompile it using 'dtc', change command line arguments, then
do reverse process and flash resulting `boot.img` to device. Sometimes it's better not to flash but to boot recovery from memory using `fastboot`.

It's enough for kernel memory dump but if you supply original **vmlinux**/**vmlinuz** file it may contain preceeding data blocks before actual kernel `.text` starts.
For example, x86-64 image often has **EFI capsule** and uboot image has it's own header.
You should substract those data blocks size from the kernel base address.

If original image is compressed everything mentioned above applies to **unpacked** image.
`extract-symvers` tries to unpack it automatically. There's `-d` option to save unpacked image to a file.
If it fails - use `binwalk` , `dd` and unpack tools - `gzip`, `xz`, `lzma`, ...

This way you find virtual address for `-B` option.

### Relocatable kernels

If `CONFIG_RELOCATABLE` was set **vmlinux** may or may not have filled addresses in structures we search for.
If not - all addresses are filled with zeroes and this script fails. This is common situation for **arm64**.
**x86** and **x86_64** kernels are pre-relocated to their default load address.

The tool [fix_kaslr](https://github.com/nforest/droidimg) helps to relocate **arm64** kernel. It expects uncompressed **vmlinux** file as input.

If it does not work or it's hard to determine kernel `.text` offset inside original file then consider to dump memory from the running system.
Unfortunately android kernels are compiled without `/dev/mem` and `/dev/kmem` support.
It is still possible to extract kernel memory contents in such case but it requires complex low level coding and hacking skills.
Fortunately much simpler approach exists. Run kernel in **QEMU**.
It will execute initial loader (`head.S`) then most likely hang because it's not compatible with **QEMU** hardware.
But it will relocate the kernel because initial loader only requires standard CPU. Then it's possible to dump memory using **QEMU**'s monitor.

example :

```
    qemu-system-aarch64 -monitor telnet:127.0.0.1:1000,server,nowait -nographic -m 256 -append "nokaslr" -M virt -cpu cortex-a57 -kernel boot-zImage
    telnet 127.0.0.1 1000
    memsave 0xFFFFFF8008080000 0x4000000 kdump.bin
```

**pmemsave** saves from physical address, **memsave** - from virtual address.
Sometimes it's easier to dump from physical address if you know exact kernel load location. Sometimes it's easier to dump from virtual address.
When dumping from a virtual address error may occur if you try to dump unmapped area.
It's important to specify valid starting virtual address. **QEMU** will dump memory until unmapped area after kernel `.text` block is reached then display an error.
If output file is not empty it's what you need.

### Extracting symvers

Usage: extract-symvers.py [options]

```
    Options:
      -h, --help            show this help message and exit
      -B ADDRESS, --base-address=ADDRESS
                            Base address (in hex) where the kernel is loaded
                            [required]
      -e ENDIANNESS, --endian=ENDIANNESS
                            Endianness (big|little|be|le) ; defaults to little/le
      -b ADDRESS, --bits=ADDRESS
                            Size of pointers in bits ; defaults to 32
      -k KVER, --kernel-version=KVER
                            Kernel version : major.minor
      -p PREL32, --prel32=PREL32
                            For kernels 4.19+ :
                            CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=[y,n]
      -d FILE, --decompress=FILE
                            Decompress the kernel to a file   
```

examples :

```
    python extract-symvers.py -b 32 -B C0008000 -k old boot-zImage
    python extract-symvers.py -b 64 -B FFFFFF8008080000 -k 4.19 -p y kdump.bin
    python extract-symvers.py -b 64 -B FFFFFFFF80E00000 -k 4.15 vmlinuz-4.15.0-1004-oem 
    python extract-symvers.py -b 32 -B C0FFF000 -k 5.15 vmlinuz-5.15-x86
    python extract-symvers.py -b 32 -B 80060000 -k 4.4 -e be /dev/mtdblock1
```

### Changes in linux affecting us

This is why it is required to supply valid kernel version number.

In kernel `4.10` they have changed `unsigned long *crcs` pointer to `s32 *crcs` in `struct symsearch`. `unsigned long` is 8 bytes on 64-bit systems but only 4 bytes are used.

`struct kernel_symbol` has changed in kernel `4.19` and `5.4` . In kernels `4.19+` it also depends on `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS`. Most likely it is enabled in newer kernels.

`struct symsearch` has changed in kernel `5.12`. It no more contains `unused` field. Also `symsearch` array no more contains entry for `WILL_BE_GPL_ONLY`.

### Not solved

This script cannot extract symbols from loaded kernel modules.
`symsearch` structure for the kernel itself is statically allocated and can be reliably found.
This is not the case for the loaded kernel modules.
To find symbols in modules kernel uses `struct module` array that describes all loaded modules.
`struct module` vary from version to version , highly depends on `CONFIG` options and also can be changed by manufactures.
It does not have reliable search pattern to extract pointers to `struct kernel_symbol` and crc array.
Possible solution would be to build a kernel module with correct kernel headers that walks through the `modules` array and extracts symbols from the kernel memory.
