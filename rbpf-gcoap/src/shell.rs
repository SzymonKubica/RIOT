use riot_wrappers::mutex::Mutex;
use riot_wrappers::shell::CommandList;

use embedded_hal::digital::v2::OutputPin;
use embedded_hal::digital::v2::ToggleableOutputPin;
use riot_wrappers::gpio;
use riot_wrappers::{cstr::cstr, stdio::println};

pub fn shell_main(countdown: &Mutex<u32>) -> Result<(), ()> {
    let mut line_buf = [0u8; 128];
    // Only include the default RIOT shell commands for now.
    // TODO: add the command to execute loaded bpf programs
    let mut commands = riot_shell_commands::all();
    let commands = trait_identity(commands).and(
        cstr!("toggle-gpio"),
        cstr!(""),
        |stdio: &mut _, args: riot_wrappers::shell::Args| {
            // accessing A5
            match (args[1].parse::<u32>(), args[2].parse::<u32>()) {
                (Ok(port), Ok(pin_num)) => {
                    // Pin d13 corresponds to the pin 5 on port A.
                    let pin =
                        gpio::GPIO::from_c(unsafe { riot_sys::macro_GPIO_PIN(port, pin_num) }).unwrap();
                    let result = pin.configure_as_output(gpio::OutputMode::Out);
                    if let Ok(mut out_pin) = result {
                        println!("Toggling GPIO port: {} pin: {}", port, pin_num);
                        if let Ok(_) = out_pin.toggle() {
                            let pin_state = unsafe { riot_sys::gpio_read(out_pin.to_c()) };
                            println!("Pin state: {}", pin_state);
                        }
                    }
                }
                _ => {}
            }
        },
    );
    trait_identity(commands).run_forever(&mut line_buf);
    unreachable!();
}

// Workaround for a bug described here: https://github.com/RIOT-OS/rust-riot-wrappers/issues/76
fn trait_identity(
    mut c: impl riot_wrappers::shell::CommandList,
) -> impl riot_wrappers::shell::CommandList {
    c
}
