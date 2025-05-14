use log::info;

#[repr(C)]
#[derive(Debug)]
pub struct Registers {
    pub xmm7: u128,
    pub xmm6: u128,
    pub xmm5: u128,
    pub xmm4: u128,
    pub xmm3: u128,
    pub xmm2: u128,
    pub xmm1: u128,
    pub xmm0: u128,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl Registers {
    pub fn from_saved_pointer(saved_registers_ptr: u64) -> Self {
        unsafe {
            let registers = std::ptr::read(saved_registers_ptr as *const Registers);
            return registers;
        }
    }
    pub fn clone(&self) -> Self {
        Registers {
            rax: self.rax,
            rbx: self.rbx,
            rcx: self.rcx,
            rdx: self.rdx,
            rsi: self.rsi,
            rdi: self.rdi,
            rbp: self.rbp,
            rsp: self.rsp,
            r8: self.r8,
            r9: self.r9,
            r10: self.r10,
            r11: self.r11,
            r12: self.r12,
            r13: self.r13,
            r14: self.r14,
            r15: self.r15,
            rflags: self.rflags,
            xmm0: self.xmm0,
            xmm1: self.xmm1,
            xmm2: self.xmm2,
            xmm3: self.xmm3,
            xmm4: self.xmm4,
            xmm5: self.xmm5,
            xmm6: self.xmm6,
            xmm7: self.xmm7,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_echo(saved_registers_ptr: u64) {
    /*
    registers are dumped in the following order:

    ; Save all registers and flags in the correct order for x86-64 ABI compliance
    ; Save flags first to preserve them before any operations
    pushfq

    ; Save all general purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; pass the stack pointer to the linux hook function
    mov rdi, rsp

     */
    // Create a Registers struct from the saved pointer
    let regs = Registers::from_saved_pointer(saved_registers_ptr);

    // Format the output using a single format! call
    let output = format!(
        "Register dump:
    rax        0x{:<16x}  {:<16}
    rbx        0x{:<16x}  {:<16}
    rcx        0x{:<16x}  {:<16}
    rdx        0x{:<16x}  {:<16}
    rsi        0x{:<16x}  {:<16}
    rdi        0x{:<16x}  {:<16}
    rbp        0x{:<16x}  0x{:<16x}
    rsp        0x{:<16x}  0x{:<16x}
    r8         0x{:<16x}  {:<16}
    r9         0x{:<16x}  {:<16}
    r10        0x{:<16x}  {:<16}
    r11        0x{:<16x}  {:<16}
    r12        0x{:<16x}  {:<16}
    r13        0x{:<16x}  {:<16}
    r14        0x{:<16x}  {:<16}
    r15        0x{:<16x}  {:<16}",
        regs.rax,
        regs.rax as i64,
        regs.rbx,
        regs.rbx as i64,
        regs.rcx,
        regs.rcx as i64,
        regs.rdx,
        regs.rdx as i64,
        regs.rsi,
        regs.rsi as i64,
        regs.rdi,
        regs.rdi as i64,
        regs.rbp,
        regs.rbp,
        regs.rsp,
        regs.rsp,
        regs.r8,
        regs.r8 as i64,
        regs.r9,
        regs.r9 as i64,
        regs.r10,
        regs.r10 as i64,
        regs.r11,
        regs.r11 as i64,
        regs.r12,
        regs.r12 as i64,
        regs.r13,
        regs.r13 as i64,
        regs.r14,
        regs.r14 as i64,
        regs.r15,
        regs.r15 as i64,
    );

    // Format flags in GDB style
    let flags = regs.rflags;
    let mut flag_names = Vec::new();

    // Common x86 flag bits
    if (flags & (1 << 0)) != 0 {
        flag_names.push("CF");
    } // Carry Flag
    if (flags & (1 << 2)) != 0 {
        flag_names.push("PF");
    } // Parity Flag
    if (flags & (1 << 4)) != 0 {
        flag_names.push("AF");
    } // Auxiliary Carry Flag
    if (flags & (1 << 6)) != 0 {
        flag_names.push("ZF");
    } // Zero Flag
    if (flags & (1 << 7)) != 0 {
        flag_names.push("SF");
    } // Sign Flag
    if (flags & (1 << 8)) != 0 {
        flag_names.push("TF");
    } // Trap Flag
    if (flags & (1 << 9)) != 0 {
        flag_names.push("IF");
    } // Interrupt Enable Flag
    if (flags & (1 << 10)) != 0 {
        flag_names.push("DF");
    } // Direction Flag
    if (flags & (1 << 11)) != 0 {
        flag_names.push("OF");
    } // Overflow Flag

    let flag_str = if !flag_names.is_empty() {
        format!("[ {} ]", flag_names.join(" "))
    } else {
        String::from("[ ]")
    };

    let output = format!("{}\n    eflags     0x{:<16x}  {}", output, flags, flag_str);

    // Log the entire output as a single message
    info!("{}", output);
}
