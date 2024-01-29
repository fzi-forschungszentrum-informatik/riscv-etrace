#![no_std]
#![no_main]
#![feature(assert_matches)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
use core::panic::PanicInfo;
#[cfg(test)]
use riscv_rt::entry;

pub mod decoder;
pub mod disassembler;
pub mod tracer;

// TODO TraceConfiguration checking
// 0 <addr width < 65
// cpu index < 2^5
// CPU_COUNT <= 2^cpu_index_width
pub struct TraceConfiguration {
    pub decompress: bool,
    pub full_address: bool,
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

pub const DEFAULT_CONFIGURATION: TraceConfiguration = TraceConfiguration {
    decompress: false,
    full_address: false,
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
    encoder_mode_n: 0,
    ioptions_n: 0,
};

//noinspection RsUnresolvedReference
#[cfg(test)]
#[entry]
fn main() -> ! {
    unsafe {
        use uart_16550::MmioSerialPort;
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
