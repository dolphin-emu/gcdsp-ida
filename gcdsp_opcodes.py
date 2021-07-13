class OpType:
    """Enumeration of the different operand encoding types which can be found
    in the GC DSP ISA. From DSPTables.h in Dolphin source code."""

    NONE = 0
    VAL = 1
    IMM = 2
    MEM = 3
    STR = 4
    ADDR_I = 5
    ADDR_D = 6

    REG = 0x8000
    REG04 = REG | 0x0400
    REG08 = REG | 0x0800
    REG18 = REG | 0x1800
    REGM18 = REG18
    REG19 = REG | 0x1900
    REGM19 = REG19
    REG1A = REG | 0x1a80
    REG1C = REG | 0x1c00
    ACCL = REG | 0x1c00
    ACCM = REG | 0x1e00
    ACCM_D = REG | 0x1e80
    ACC = REG | 0x2000
    ACC_D = REG | 0x2080
    AX = REG | 0x2200
    REGS_MASK = 0x3f80

    REF = REG | 0x4000
    PRG = REF | REG
