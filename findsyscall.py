import idc
import idaapi
import idautils
import ida_kernwin
import ida_ida
import ida_idp
import find_syscall_uitls

def getcpu():
    # https://www.hex-rays.com/products/ida/support/idadoc/618.shtml
    # 'PLFM_386', 'PLFM_6502', 'PLFM_65C816', 'PLFM_6800', 'PLFM_68K', 'PLFM_80196', 'PLFM_8051', 'PLFM_AD2106X', 'PLFM_AD218X', 'PLFM_ALPHA', 'PLFM_ARC', 'PLFM_ARM', 'PLFM_AVR', 'PLFM_C166', 'PLFM_C39', 'PLFM_CR16', 'PLFM_DALVIK', 'PLFM_DSP56K', 'PLFM_DSP96K', 'PLFM_EBC', 'PLFM_F2MC', 'PLFM_FR', 'PLFM_H8', 'PLFM_H8500', 'PLFM_HPPA', 'PLFM_I860', 'PLFM_I960', 'PLFM_IA64', 'PLFM_JAVA', 'PLFM_KR1878', 'PLFM_M16C', 'PLFM_M32R', 'PLFM_M740', 'PLFM_M7700', 'PLFM_M7900', 'PLFM_MC6812', 'PLFM_MC6816', 'PLFM_MIPS', 'PLFM_MN102L00', 'PLFM_MSP430', 'PLFM_NEC_78K0', 'PLFM_NEC_78K0S', 'PLFM_NEC_V850X', 'PLFM_NET', 'PLFM_OAKDSP', 'PLFM_PDP', 'PLFM_PIC', 'PLFM_PIC16', 'PLFM_PPC', 'PLFM_RISCV', 'PLFM_RL78', 'PLFM_RX', 'PLFM_S390', 'PLFM_SCR_ADPT', 'PLFM_SH', 'PLFM_SPARC', 'PLFM_SPC700', 'PLFM_SPU', 'PLFM_ST20', 'PLFM_ST7', 'PLFM_ST9', 'PLFM_TLCS900', 'PLFM_TMS', 'PLFM_TMS320C1X', 'PLFM_TMS320C28', 'PLFM_TMS320C3', 'PLFM_TMS320C54', 'PLFM_TMS320C55', 'PLFM_TMSC6', 'PLFM_TRICORE', 'PLFM_TRIMEDIA', 'PLFM_UNSP', 'PLFM_XTENSA', 'PLFM_Z8', 'PLFM_Z80'
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "386",
        ida_idp.PLFM_ARM: "arm",
        ida_idp.PLFM_PPC: "ppc",
        ida_idp.PLFM_MIPS: "mips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % cpu)
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "64"
        else:
            decompiler += "64"
        
    return decompiler

syscalls = find_syscall_uitls.syscalls()
cpuabi = getcpu()

def syscall_info(addr):
    head_addr = idc.prev_head(addr)
    head_disasm = idc.GetDisasm(head_addr)
    op_type = idc.get_operand_type(head_addr,1)
    
    if(op_type == 5) and ("MOV" in idc.GetDisasm(head_addr)):

        syscall_num = idc.get_operand_value(head_addr, 1)
        
        if(syscalls.get(cpuabi, syscall_num)):
            out_info = f"{hex(addr)} | {syscalls.get(cpuabi, syscall_num)} ===> {head_disasm.replace('      ', ' ')}"
            return out_info

    return f"wran: {hex(addr)}"

def findsy_scall():
    print("-------syscall scan start------")
    print(f"------cpuabi:{cpuabi}------")

    # arm64, arm, arm(thumb)
    _support_abi_list = ["arm64", "arm"]

    _syscall_set = set()
    if cpuabi in _support_abi_list:
        pattern = 'svc ?'
        addr = ida_ida.inf_get_min_ea()
        end = ida_ida.inf_get_max_ea()
        while addr < end:
            addr = idc.find_text(addr, idc.ida_search.SEARCH_REGEX|idc.ida_search.SEARCH_DOWN, 0, 0, pattern)
            if addr != idc.BADADDR and not addr in _syscall_set:
                _syscall_set.add(addr)
                info = syscall_info(addr)
                print(info)
            else:
                addr = idc.next_head(addr)

class findSysCall(idaapi.plugin_t):
    def __init__(self):
        self.flags = idaapi.PLUGIN_UNL
        self.comment = "FindSysCall"
        self.help = "FindSysCall"
        self.wanted_name = "FindSysCall"
        self.wanted_hotkey = ""
    def init(self):
        return idaapi.PLUGIN_OK
    def term(self):
        pass
    def run(self, args):
        findsy_scall()

def PLUGIN_ENTRY():
    return findSysCall()