use log::{info, LevelFilter};
use std::sync::Once;

static INIT: Once = Once::new();

fn initialize_logger() {
    INIT.call_once(|| {
        let log_path = "/tmp/le_lib.log";
        let config = log4rs::append::file::FileAppender::builder()
            .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new("{d} {l} {t} - {m}{n}")))
            .build(log_path)
            .unwrap();

        let config = log4rs::config::Config::builder()
            .appender(log4rs::config::Appender::builder().build("file", Box::new(config)))
            .build(log4rs::config::Root::builder()
                .appender("file")
                .build(LevelFilter::Info))
            .unwrap();

        log4rs::init_config(config).expect("Failed to initialize logger");
        info!("le_lib logger initialized");
    });
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

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
        rax: 0, rbx: 0, rcx: 0, rdx: 0,
        rsi: 0, rdi: 0, rbp: 0, rsp: 0,
        r8: 0, r9: 0, r10: 0, r11: 0,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rip: 0, rflags: 0,
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
        // This is not exact but gives us a value near the call point
        std::arch::asm!(
            "lea {rip}, [rip]",
            rip = out(reg) regs.rip,
        );
    }
    
    regs
}

#[unsafe(no_mangle)]
pub extern "C" fn le_lib_echo() {
    initialize_logger();
    
    // Safely capture registers
    let regs = unsafe { capture_registers() };
    
    info!("Register dump:");
    info!("RAX: 0x{:016x}", regs.rax);
    info!("RBX: 0x{:016x}", regs.rbx);
    info!("RCX: 0x{:016x}", regs.rcx);
    info!("RDX: 0x{:016x}", regs.rdx);
    info!("RSI: 0x{:016x}", regs.rsi);
    info!("RDI: 0x{:016x}", regs.rdi);
    info!("RBP: 0x{:016x}", regs.rbp);
    info!("RSP: 0x{:016x}", regs.rsp);
    info!("R8:  0x{:016x}", regs.r8);
    info!("R9:  0x{:016x}", regs.r9);
    info!("R10: 0x{:016x}", regs.r10);
    info!("R11: 0x{:016x}", regs.r11);
    info!("R12: 0x{:016x}", regs.r12);
    info!("R13: 0x{:016x}", regs.r13);
    info!("R14: 0x{:016x}", regs.r14);
    info!("R15: 0x{:016x}", regs.r15);
    info!("RIP: 0x{:016x}", regs.rip);
    info!("RFLAGS: 0x{:016x}", regs.rflags);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        le_lib_echo();
    }
}
