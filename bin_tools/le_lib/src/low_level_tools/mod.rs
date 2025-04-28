// Low level tools module for handling assembly compilation and memory injection
// This module isolates functionality that interfaces with system-level operations

pub mod compiler;
pub mod injector;

// Re-export key functions for convenience
pub use compiler::{compile_assembly_local, compile_assembly_remote};
pub use injector::inject_hook;
