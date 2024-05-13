//! # Rust implementation of Efficient Trace for RISC-V's instruction decoder and tracing algorithm (Version 2.0.1)
//!
//! This project implements the instruction packet decoder and instruction tracing algorithm for
//! [Efficient Trace for RISC-V (Version 2.0.1)](https://github.com/riscv-non-isa/riscv-trace-spec/).
//! It assumes each packet is written in a given specific memory location. This crate is not
//! concerned how the encoder signals a new packet or how the packet is transported to the decoder.
//!
//! See [decoder] for the implementation of the packet decoder and [tracer] for the tracing
//! algorithm.
//!
//! # ETrace features
//! - instruction tracing
//! - delta/full address mode
//! - configurable bit width of packet fields
//! - (partially implemented) optional context for instructions
//! - (partially implemented) optional timestamp in header
//! - (not yet implemented) optional implicit return mode
//!
//! # Example
//! ```
//! extern crate decoder;
//!
//! use decoder::{DecoderConfiguration, DEFAULT_PROTOCOL_CONFIG, ProtocolConfiguration, TraceConfiguration};
//! use decoder::decoder::{Decoder, DEFAULT_PACKET_BUFFER_LEN};
//! use decoder::disassembler::Instruction;
//! use decoder::segment::Segment;
//! use decoder::tracer::Tracer;
//!
//! // Create your segments from your ELF files.
//! let mut segments: Vec<Segment> = Vec::new();
//!
//! // Create the protocol level configuration which will define the bit lengths of packet fields.
//! let proto_conf = ProtocolConfiguration {
//!     // In this example we assume a maximum of 2^10   of CPU cores...
//!     cpu_index_width: 10,
//!     // ...but everything else will be default.
//!     ..DEFAULT_PROTOCOL_CONFIG
//! };
//!
//! // Create the decoder configuration.
//! let decoder_conf = DecoderConfiguration {
//!     decompress: false,
//! };
//!
//! // A single tracing configuration will be used for all tracers.
//! let trace_conf = TraceConfiguration {
//!     // Pass your parsed ELF segments.
//!     segments: &segments,
//!     // We will use compressed addresses for better efficiency.
//!     full_address: false,
//! };
//!
//! // Define your report callbacks such as report_pc:
//! let report_pc = |reason, pc| println!("pc: 0x{:x} ({:?})", pc, reason);
//! let report_epc = |epc| println!("epc: 0x{:x}", epc);
//! let report_trap = |trap| println!("trap: {:?}", trap);
//! let report_instr = |instr: Instruction| { println!("instr: {:?}", instr) };
//! let report_branch = |branches: usize, branch_map: u32, local_taken: bool|
//!     { println!("branch: {:?} {:032b} {}", branches, branch_map, local_taken) };
//!
//! // Create the packet decoder.
//! let mut decoder = Decoder::new(proto_conf, decoder_conf);
//!
//! // Create each tracer, one for each hart.
//! let mut tracers: Vec<Tracer> = Vec::new();
//! for i in 0..1024 {
//!     tracers.push(Tracer::new(
//!             proto_conf,
//!             trace_conf,
//!             report_pc,
//!             report_epc,
//!             report_trap,
//!             report_instr,
//!             report_branch,
//!         ));
//! }
//!
//! // Assuming we have a slice given with a packet already written in binary in it:
//! # let packet_vec: Vec<u8> = Vec::new();
//! #
//! # let packet_slice: [u8; DEFAULT_PACKET_BUFFER_LEN] = [0; DEFAULT_PACKET_BUFFER_LEN];
//! let packet = decoder.decode(packet_slice).unwrap();
//! println!("{:?}", packet);
//!
//! // Get the correct tracer based on the CPU index...
//! let mut tracer = &tracers[packet.header.cpu_index];
//! // ...and trace it.
//! tracer.process_te_inst(&packet.payload).unwrap();
//! ```
#![no_std]
#![no_main]
#![feature(assert_matches)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use crate::segment::Segment;
#[cfg(test)]
use core::panic::PanicInfo;
#[cfg(test)]
use riscv_rt::entry;

pub mod decoder;
pub mod disassembler;
pub mod segment;
pub mod tracer;

#[derive(Copy, Clone)]
pub struct ProtocolConfiguration {
    #[cfg(feature = "context")]
    pub context_width_p: usize,
    #[cfg(feature = "time")]
    pub time_width_p: usize,
    pub ecause_width_p: usize,
    pub iaddress_lsb_p: usize,
    pub iaddress_width_p: usize,
    pub cache_size_p: usize,
    pub privilege_width_p: usize,
    pub cpu_index_width: usize,
    pub encoder_mode_n: usize,
    pub ioptions_n: usize,
}

#[derive(Copy, Clone)]
pub struct DecoderConfiguration {
    pub decompress: bool,
}

#[derive(Copy, Clone)]
pub struct TraceConfiguration<'a> {
    pub segments: &'a [Segment],
    pub full_address: bool,
}

pub const DEFAULT_PROTOCOL_CONFIG: ProtocolConfiguration = ProtocolConfiguration {
    #[cfg(feature = "context")]
    context_width_p: 0,
    #[cfg(feature = "time")]
    time_width_p: 0,
    ecause_width_p: 6,
    iaddress_lsb_p: 1,
    iaddress_width_p: 64,
    cache_size_p: 0,
    privilege_width_p: 2,
    cpu_index_width: 0,
    encoder_mode_n: 1,
    ioptions_n: 5,
};

pub const DEFAULT_DECODER_CONFIG: DecoderConfiguration = DecoderConfiguration { decompress: false };

#[cfg(test)]
#[entry]
fn main() -> ! {
    use uart_16550::MmioSerialPort;
    unsafe {
        let mut serial = MmioSerialPort::new(serial::SERIAL_PORT_BASE_ADDRESS);
        serial.init();
        serial::SERIAL1 = Some(serial)
    }
    test_main();
    exit_qemu::success()
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu::failure()
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu::success()
}

#[cfg(test)]
pub trait Testable {
    fn run(&self) -> ();
}

#[cfg(test)]
impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{:48}\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

#[cfg(test)]
mod serial {
    use uart_16550::MmioSerialPort;

    pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

    pub static mut SERIAL1: Option<MmioSerialPort> = None;

    #[doc(hidden)]
    pub fn _print(args: core::fmt::Arguments) {
        use core::fmt::Write;
        unsafe {
            SERIAL1
                .as_mut()
                .unwrap_unchecked()
                .write_fmt(args)
                .expect("Printing to serial failed");
        }
    }

    /// Prints to the host through the serial interface.
    #[macro_export]
    macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*));
    };
}

    /// Prints to the host through the serial interface, appending a newline.
    #[macro_export]
    macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*));
    }
}

#[cfg(test)]
mod exit_qemu {
    use core::arch::asm;

    const ADDR: u32 = 0x100000;
    const EXIT_FAILURE: u32 = 0x3333;
    const EXIT_SUCCESS: u32 = 0x5555;

    pub fn failure() -> ! {
        exit(EXIT_FAILURE);
    }

    pub fn success() -> ! {
        exit(EXIT_SUCCESS);
    }

    fn exit(value: u32) -> ! {
        unsafe {
            asm!(
            "sw {0}, 0({1})",
            in(reg)value, in(reg)ADDR
            );
            loop {
                asm!("wfi", options(nomem, nostack));
            }
        }
    }
}
