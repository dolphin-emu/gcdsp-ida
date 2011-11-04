"""
gcdsp.py
~~~~~~~~

An IDAPython processor module for the GC/Wii DSP.

Copyright (C) 2011 Pierre Bourdon <delroth@lse.epita.fr>
Copyright (C) 2011 Stephane Sezer <stephane@lse.epita.fr>

Licensed under the New BSD License, see the LICENSE file at the root of this
repository.
"""
from idaapi import *

GREETINGS_STRING = """\
GC/Wii DSP processor for IDA (C) 2011 LSE (http://lse.epita.fr/) - licensed \
under the New BSD License\
"""

class Instr(object):
    def __init__(self, name, uses=[], changes=[], stops=False, calls=False,
                 jumps=False, shifts=False, hll=False):
        self.name = name
        self.uses = uses
        self.changes = changes
        self.stops = stops
        self.calls = calls
        self.jumps = jumps
        self.shifts = shifts
        self.hll = hll

    @property
    def flags(self):
        ret = 0
        for use in self.uses:
            ret |= CF_USE1 << use
        for change in self.changes:
            ret |= CF_CHG1 << change
        if self.stops:
            ret |= CF_STOP
        if self.calls:
            ret |= CF_CALL
        if self.jumps:
            ret |= CF_JUMP
        if self.shifts:
            ret |= CF_SHFT
        if self.hll:
            ret |= CF_HLL
        return ret

class GCDSPProcessor(processor_t):
    id = 0x8000 + 5854
    flag = PR_ADJSEGS | PRN_HEX | PR_WORD_INS
    cnbits = 16
    dnbits = 16
    psnames = ["gcdsp"]
    plnames = ["GC/Wii DSP"]
    segreg_size = 0

    instruc_start = 0

    assembler = {
        "flag" : ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_NOTAB
               | AS_ASCIIC | AS_ASCIIZ,
        "uflag": 0,
        "name": "GNU assembler",

        "origin": ".org",
        "end": "end",
        "cmnt": ";",

        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",

        "a_ascii": ".ascii",
        "a_byte": ".word",
        "a_word": ".dword",

        "a_bss": "dfs %s",

        "a_seg": "seg",
        "a_curip": ".",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extrn",
        "a_comdef": "",
        "a_align": ".align",

        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "AR0", "AR1", "AR2", "AR3",
        "IX0", "IX1", "IX2", "IX3",
        "WR0", "WR1", "WR2", "WR3",
        "ST0", "ST1", "ST2", "ST3",
        "AC0.H", "AC1.H",
        "CR", "SR",
        "PROD.L", "PROD.M1", "PROD.H", "PROD.M2",
        "AX0.L", "AX1.L", "AX0.H", "AX1.H",
        "AC0.L", "AC1.L", "AC0.M", "AC1.M",
        "ACC0", "ACC1",
        "AX0", "AX1",
        "CS", "DS"
    ]

    instrs_list = [
        Instr("NOP"),
        Instr("CALL", uses=[0], calls=True),
        Instr("RET", stops=True),
    ]

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        """Setup instructions parameters for IDA."""
        self.instruc = [{ "name": i.name, "feature": i.flags }
                        for i in self.instrs_list]
        self.instruc_end = len(self.instruc)

        self.instrs = {}
        for instr in self.instrs_list:
            self.instrs[instr.name] = instr

        self.instrs_ids = {}
        for i, instr in enumerate(self.instrs_list):
            self.instrs_ids[instr.name] = i

    def _init_registers(self):
        """Setup registers index and special register values."""

        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i

        # Simulate fake segment registers
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def notify_init(self, idp_file):
        """Called at module initialization."""
        cvar.inf.mf = True  # set to big endian... wtf
        cvar.inf.wide_high_byte_first = True  # big endian for 16b bytes too
        return True

    def notify_endbinary(self, ok):
        """Called when the binary finished loading."""
        if ok:
            print GREETINGS_STRING

    def ana(self):
        """Analyze one instruction and fill the "cmd" global value."""
        return

    def emu(self):
        """Emulate instruction behavior and create x-refs, interpret operand
        values, etc."""
        return

    def outop(self, op):
        """Generates text representation of an instruction operand."""
        return

    def out(self):
        """Generates text representation of an instruction in the "cmd" global
        value."""
        return

def PROCESSOR_ENTRY():
    return GCDSPProcessor()
