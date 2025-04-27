use log::info;

#[repr(C)]
#[derive(Debug)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// Captures current register state with no-op assembly that preserves all registers
unsafe fn capture_registers() -> Registers {
    let mut regs = Registers {
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: 0,
        rsp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: 0,
        rflags: 0,
    };

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // First block: capture first set of registers
        std::arch::asm!(
            "mov {rax}, rax",
            "mov {rbx}, rbx",
            "mov {rcx}, rcx",
            "mov {rdx}, rdx",
            "mov {rsi}, rsi",
            "mov {rdi}, rdi",
            "mov {rbp}, rbp",
            "mov {rsp}, rsp",
            "pushfq",
            "pop {rflags}",
            rax = out(reg) regs.rax,
            rbx = out(reg) regs.rbx,
            rcx = out(reg) regs.rcx,
            rdx = out(reg) regs.rdx,
            rsi = out(reg) regs.rsi,
            rdi = out(reg) regs.rdi,
            rbp = out(reg) regs.rbp,
            rsp = out(reg) regs.rsp,
            rflags = out(reg) regs.rflags,
        );

        // Second block: capture remaining registers
        std::arch::asm!(
            "mov {r8}, r8",
            "mov {r9}, r9",
            "mov {r10}, r10",
            "mov {r11}, r11",
            "mov {r12}, r12",
            "mov {r13}, r13",
            "mov {r14}, r14",
            "mov {r15}, r15",
            r8 = out(reg) regs.r8,
            r9 = out(reg) regs.r9,
            r10 = out(reg) regs.r10,
            r11 = out(reg) regs.r11,
            r12 = out(reg) regs.r12,
            r13 = out(reg) regs.r13,
            r14 = out(reg) regs.r14,
            r15 = out(reg) regs.r15,
        );

        // Get an approximation of RIP by taking the return address from the stack
        std::arch::asm!(
            "lea {rip}, [rip]",
            rip = out(reg) regs.rip,
        );
    }

    regs
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_echo() {
    crate::initialize_logger();

    // Safely capture registers
    let regs = unsafe { capture_registers() };

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
    r15        0x{:<16x}  {:<16}
    rip        0x{:<16x}  0x{:<16x} <main>",
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
        regs.rip,
        regs.rip,
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
