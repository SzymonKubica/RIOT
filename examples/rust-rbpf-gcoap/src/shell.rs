use riot_wrappers::mutex::Mutex;
use riot_wrappers::shell::CommandList;

pub fn shell_main(countdown: &Mutex<u32>) -> Result<(), ()> {
    // This is the lock that's held during countdown pauses. As commands may take mutable closures,
    // no synchronization is necessary -- CommmandList wrappers ensure the compiler that no two
    // commands will be run at the same time.

    let mut line_buf = [0u8; 128];

    let mut commands = riot_shell_commands::all();
    commands.run_forever(&mut line_buf);
    unreachable!();
}
