// Copyright (C) 2020 Christian Amsüss
//
// This file is subject to the terms and conditions of the GNU Lesser
// General Public License v2.1. See the file LICENSE in the top level
// directory for more details.
#![no_std]

use core::fmt::Write;
use riot_wrappers::riot_main;
use riot_wrappers::{gcoap, thread, ztimer, gnrc, mutex::Mutex, stdio::println, riot_sys};
use riot_wrappers::shell::CommandList;
use riot_wrappers::cstr::cstr;
use embedded_nal::UdpClientStack;

use coap_handler_implementations::SimpleRendered;

static SECONDTHREAD_STACK: Mutex<[u8; 16384]> = Mutex::new([0; 16384]);

extern crate rust_riotmodules;

riot_main!(main);

fn main() {
    extern "C" {
        fn do_vfs_init();
        fn do_gnrc_msg_queue_init();
    }

    unsafe { do_vfs_init() };
    unsafe { do_gnrc_msg_queue_init() };

    let countdown = Mutex::new(3);

    // One can either allocate the stack for the new thread statically (and ensure via a mutex that
    // it's only used once), or...
    let mut secondthread_stacklock = SECONDTHREAD_STACK.lock();
    let mut gcoapthread_mainclosure = || gcoap_server_thread_main_2(&countdown).unwrap();

    // ... or plainly allocate it on another thread's stack. In both cases, usually, the
    // spawning thread must outlive the child. (In the former, there might be the option to move
    // out Thread object and the stack reference).
    let mut shellthread_stack = [0u8; 5120];
    let mut shellthread_mainclosure = || shellthread_main(&countdown).unwrap();

    thread::scope(|threadscope| {

    let secondthread = threadscope.spawn(
        secondthread_stacklock.as_mut(),
        &mut gcoapthread_mainclosure,
        cstr!("secondthread"),
        (riot_sys::THREAD_PRIORITY_MAIN - 2) as _,
        (riot_sys::THREAD_CREATE_STACKTEST) as _,
    ).expect("Failed to spawn second thread");

    println!("Second thread spawned as {:?} ({:?}), status {:?}", secondthread.pid(), secondthread.pid().get_name(), secondthread.status());

    let shellthread = threadscope.spawn(
        shellthread_stack.as_mut(),
        &mut shellthread_mainclosure,
        cstr!("shellthread"),
        (riot_sys::THREAD_PRIORITY_MAIN - 1) as _,
        (riot_sys::THREAD_CREATE_STACKTEST) as _,
    ).expect("Failed to spawn shell thread");

    println!("Shell thread spawned as {:?} ({:?}), status {:?}", shellthread.pid(), shellthread.pid().get_name(), shellthread.status());

    // Terminating the main thread will lead to some serious quarrel from the destructors of
    // thread, for we can't just std::process::Child::wait() on them to free up anything we'd have
    // passed in -- so rather than doing this loop at the ensuring panic, we enter it deliberately.
    loop {
        thread::sleep();
    }

    // If we knew they had terminated, we could just collect them; see
    // riot_wrappers::thread::CountingThreadScope::reap documentation for why that doesn't block.
    // threadscope.reap(secondthread);
    // threadscope.reap(shellthread);
    // Reaching here without having called the reaps would panic, but we have an endless loop
    // before anyway
    });

    unreachable!();
}

pub fn full_application_tree() -> impl coap_handler::Handler + coap_handler::Reporting {

    use coap_handler_implementations::{new_dispatcher, HandlerBuilder, ReportingHandlerBuilder, TypeHandler};

    use coap_handler::Attribute::*;

    let handler = new_dispatcher()
        .at_with_attributes(&[], &[Ct(0), Title("Landing page")], WELCOME)
        .at_with_attributes(&["board"], &[Ct(0), Title("Riot board information")], BOARD);

    handler
        .with_wkc()
}

pub static WELCOME: SimpleRendered<&str> = SimpleRendered("Hello CoAP");
pub static BOARD: SimpleRendered<RiotBoardHandler> = SimpleRendered(RiotBoardHandler);


fn gcoap_server_thread_main_2(countdown: &Mutex<u32>) -> Result<(), ()> {
    let handler = full_application_tree();
        //.below(&["ps"], riot_coap_handler_demos::ps::ps_tree())
        //.below(&["vfs"], riot_coap_handler_demos::vfs::vfs("/const"))
        //.with_wkc()
        //;
    let mut handler = riot_wrappers::coap_handler::GcoapHandler(handler);

    let mut listener = gcoap::SingleHandlerListener::new_catch_all(&mut handler);

    gcoap::scope(|greg| {
        greg.register(&mut listener);

        println!("CoAP server ready; waiting for interfaces to settle before reporting addresses...");

        let sectimer = ztimer::Clock::sec();
        sectimer.sleep_ticks(2);

        for netif in gnrc::Netif::all() {
            println!("Active interface from PID {:?} ({:?})", netif.pid(), netif.pid().get_name().unwrap_or("unnamed"));
            match netif.ipv6_addrs() {
                Ok(addrs) => {
                    for a in &addrs {
                        println!("    Address {:?}", a);
                    }
                }
                _ => {
                    println!("    Does not support IPv6.");
                }
            }
        }

        // Sending main thread to sleep; can't return or the Gcoap handler would need to be
        // deregistered (which it can't).
        loop { thread::sleep(); }
    });

    Ok(())
}

/// Thread for the shell CLI
fn shellthread_main(countdown: &Mutex<u32>) -> Result<(), ()> {
    // This is the lock that's held during countdown pauses. As commands may take mutable closures,
    // no synchronization is necessary -- CommmandList wrappers ensure the compiler that no two
    // commands will be run at the same time.

    let mut line_buf = [0u8; 128];

    let mut commands = riot_shell_commands::all();
    commands.run_forever(&mut line_buf);
    Ok(())
}

fn gcoap_server_thread_main(countdown: &Mutex<u32>) -> Result<(), ()>  {
    println!("Preparing CoAP server");

    // FIXME given we're using this in a "One read-modify-writes, others read only" pattern, there
    // might be a better abstraction
    let req_count = core::cell::Cell::new(0);

    let mut riot_board_handler = riot_wrappers::coap_handler::GcoapHandler(SimpleRendered(RiotBoardHandler));
    let mut stats_handler = riot_wrappers::coap_handler::GcoapHandler(SimpleRendered(StatsHandler(&req_count)));

    // Rather than having a single handler, dispatch could be handled by a coap_handler (but then
    // it's not exposed that nicely via .well-known/ocre), or by something better than
    // SingleHandlerListener that builds a non-single listener.
    let mut boardlistener = gcoap::SingleHandlerListener::new(cstr!("/riot/board"), riot_sys::COAP_GET, &mut riot_board_handler);
    let mut statslistener = gcoap::SingleHandlerListener::new(cstr!("/cli/stats"), riot_sys::COAP_GET | riot_sys::COAP_PUT, &mut stats_handler);

    gcoap::scope(|greg| {
        greg.register(&mut boardlistener);
        greg.register(&mut statslistener);

        loop { thread::sleep(); }
    })
}

#[derive(Copy, Clone)]
struct RiotBoardHandler;
impl coap_handler_implementations::SimpleRenderable for RiotBoardHandler {
    fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
        println!("Request for the riot board name received");
        writeln!(writer, "{}",
                 core::str::from_utf8(riot_sys::RIOT_BOARD)
                     .expect("Oddly named board crashed CoAP stack")
            ).unwrap();

        // Compared to the C example, there is no "message too small" error case as
        // SimpleRenderable would use block-wise transfer in such cases.
    }
        fn content_format(&self) -> Option<u16> {
        Some(0 /* text/plain */)
    }

}

// PUT is missing, would need a more manual implementation or an extension to SimpleRenderable that
// has some read-able version as well.
struct StatsHandler<'a>(&'a core::cell::Cell<u32>);
impl<'a> coap_handler_implementations::SimpleRenderable for StatsHandler<'a> {
    fn render<W: core::fmt::Write>(&mut self, writer: &mut W) {
        writeln!(writer, "{}", self.0.get()).unwrap();
    }
}

