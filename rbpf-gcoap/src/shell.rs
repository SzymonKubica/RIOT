use riot_wrappers::mutex::Mutex;
use riot_wrappers::shell::CommandList;

pub fn shell_main(countdown: &Mutex<u32>) -> Result<(), ()> {
    let mut line_buf = [0u8; 128];
    // Only include the default RIOT shell commands for now.
    // TODO: add the command to execute loaded bpf programs
    let mut commands = riot_shell_commands::all();
    commands.run_forever(&mut line_buf);
    unreachable!();
}
