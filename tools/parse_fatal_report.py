#!/usr/bin/env python3
"""Decode an Atmosphère fatal-error report (sdmc:/atmosphere/fatal_errors/report_*.bin).

Layout: ams::impl::FatalErrorContext, see
Atmosphere-libs/libvapours/include/vapours/ams/ams_fatal_error_context.hpp (sizeof == 0x450).

Usage:
    python tools/parse_fatal_report.py report_0000000010b69933.bin
    python tools/parse_fatal_report.py report_....bin --elf ldn_mitm.elf   # symbolize

The optional ELF symbolizer only needs .symtab/.strtab, so a normal (non-stripped)
`ldn_mitm.elf` from `out/` or the build directory is enough.
"""
import struct
import sys

ERROR_DESC = {
    0xFFE: "StdAbortErrorDesc (standard abort: AMS_ABORT / AMS_ABORT_UNLESS / assert / C++ throw)",
    0xFFD: "StackOverflowErrorDesc",
    0xF00: "KernelPanicDesc",
    0x101: "DataAbortErrorDesc",
}

TITLE_NAMES = {
    0x4200000000000010: "ldn_mitm (this fork's sysmodule)",
}


def version_str(v):
    """hos version: (major << 24) | (minor << 16) | (micro << 8) | rev."""
    return "%u.%u.%u.%u" % ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


def ams_version_str(v):
    """Atmosphere release version: MAKE_VERSION(major, minor, micro) = (major << 16) | (minor << 8) | micro."""
    return "%u.%u.%u" % ((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


class ElfSymbols:
    """Minimal ELF64 little-endian symbol-table lookup (no external deps)."""

    def __init__(self, path):
        with open(path, "rb") as f:
            data = f.read()
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type, _, _, sh_offset, sh_size, sh_link = struct.unpack_from("<IIQQQQI", data, off)
            sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link))
        self.symbols = []
        for sh_name, sh_type, sh_offset, sh_size, sh_link in sections:
            if sh_type != 2 or sh_link >= len(sections):  # SHT_SYMTAB
                continue
            str_off, str_size = sections[sh_link][2], sections[sh_link][3]
            strtab = data[str_off:str_off + str_size]
            count = sh_size // 24
            for i in range(count):
                name_off, info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", data, sh_offset + i * 24)
                if value == 0 or size == 0:
                    continue
                end = strtab.find(b"\0", name_off)
                name = strtab[name_off:end].decode("utf-8", "replace") if name_off < len(strtab) else ""
                self.symbols.append((value, size, name))
        self.symbols.sort()

    def lookup(self, addr):
        best = None
        for value, size, name in self.symbols:
            if value <= addr < value + size:
                best = (name, addr - value, size)
            elif value > addr:
                break
        return best


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    path = argv[1]
    elf_path = None
    if "--elf" in argv:
        elf_path = argv[argv.index("--elf") + 1]

    with open(path, "rb") as f:
        buf = f.read()
    if len(buf) != 0x450:
        print("warning: size is %#x, expected 0x450 (layout may differ)" % len(buf))

    magic, error_desc, program_id = struct.unpack_from("<IIQ", buf, 0)
    gprs = list(struct.unpack_from("<32Q", buf, 0x10))
    pc, module_base = struct.unpack_from("<QQ", buf, 0x110)
    pstate, afsr0, afsr1, esr = struct.unpack_from("<IIII", buf, 0x120)
    far, report_id, trace_size, dump_size = struct.unpack_from("<QQQQ", buf, 0x130)
    trace = list(struct.unpack_from("<32Q", buf, 0x150))

    print("file:            %s" % path)
    print("magic:           %s" % buf[0:4].decode("ascii", "replace"))
    print("error_desc:      %#06x  %s" % (error_desc, ERROR_DESC.get(error_desc, "(unknown)")))
    print("program_id:      %#018x  %s" % (program_id, TITLE_NAMES.get(program_id, "")))
    print("atmosphere:      %s (0x%08x)" % (ams_version_str(afsr0), afsr0))
    print("system version:  %s (0x%08x)" % (version_str(afsr1), afsr1))
    print("module_base:     %#x" % module_base)
    print("pc:              %#x  (+%#x)" % (pc, pc - module_base))
    print("sp:              %#x" % gprs[31])
    print("lr:              %#x  (+%#x)" % (gprs[30], gprs[30] - module_base))
    print("fp:              %#x" % gprs[29])
    print("far:             %#x" % far)
    print("pstate:          %#x   esr: %#x" % (pstate, esr))
    print("report_id:       %#x  (~%.1f s of 19.2 MHz ticks)" % (report_id, report_id / 19200000.0))
    print("x0:              %#x   x27: %#x   x28: %#x" % (gprs[0], gprs[27], gprs[28]))
    if gprs[27] == 0x8 and gprs[28] == 0xA55AF00DDEADCAFE:
        print("  -> standard abort marker present; x0 carries the value passed to AbortWithValue()")
        print("     x0 == 0  : unconditional abort / assert / unreachable / C++ throw wrapper")
        print("     x0 != 0  : R_ABORT_UNLESS(...) failed with that Result")
    print("stack trace:     %u frame(s)" % trace_size)
    syms = ElfSymbols(elf_path) if elf_path else None
    for i in range(min(trace_size, 32)):
        addr = trace[i]
        line = "  [%2u] %#x  (+%#x)" % (i, addr, addr - module_base)
        if syms:
            hit = syms.lookup(addr - module_base)  # ELF is linked at 0, module loaded at module_base
            if hit:
                line += "  %s+%#x" % (hit[0], hit[1])
        print(line)
    if syms:
        for label, addr in (("pc", pc), ("lr", gprs[30])):
            hit = syms.lookup(addr - module_base)
            if hit:
                print("%s symbol:      %s+%#x" % (label, hit[0], hit[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
