// Copyright (C) 2020 Christian Amsüss
//
// This file is subject to the terms and conditions of the GNU Lesser
// General Public License v2.1. See the file LICENSE in the top level
// directory for more details.
#![no_std]

use riot_wrappers::riot_main;
use riot_wrappers::{mutex::Mutex, stdio::println, thread, ztimer};
use riot_wrappers::cstr::cstr;

mod coap_server;
mod shell;
mod handlers;
mod allocator;


// The second thread is running the CoAP network stack, therefore its
// stack memory size needs to be appropriately larger.
// The threading setup was adapted from here: https://gitlab.com/etonomy/riot-examples/-/tree/master/shell_threads?ref_type=heads
static COAP_THREAD_STACK: Mutex<[u8; 16384]> = Mutex::new([0; 16384]);
static SHELL_THREAD_STACK: Mutex<[u8; 5120]> = Mutex::new([0; 5120]);

extern crate rust_riotmodules;
extern crate rbpf;
extern crate alloc;
extern crate riot_sys;

riot_main!(main);

fn main() {
    extern "C" {
        fn do_gnrc_msg_queue_init();
    }

    // Need to initialise the gnrc message queue to allow for using
    // shell utilities such as ifconfig and ping
    // Not sure how it works, adapted from examples/suit_femtocontainer/gcoap_handler.c
    unsafe { do_gnrc_msg_queue_init() };

    // Allows for inter-thread synchronization, not used at the moment.
    let countdown = Mutex::new(3);

    // Lock the stacks of the threads.
    let mut secondthread_stacklock = COAP_THREAD_STACK.lock();
    let mut shellthread_stacklock = SHELL_THREAD_STACK.lock();

    let mut gcoapthread_mainclosure = || coap_server::gcoap_server_main(&countdown).unwrap();
    let mut shellthread_mainclosure = || shell::shell_main(&countdown).unwrap();

    // Spawn the threads and then wait forever.
    thread::scope(|threadscope| {
        let secondthread = threadscope
            .spawn(
                secondthread_stacklock.as_mut(),
                &mut gcoapthread_mainclosure,
                cstr!("secondthread"),
                (riot_sys::THREAD_PRIORITY_MAIN - 2) as _,
                (riot_sys::THREAD_CREATE_STACKTEST) as _,
            )
            .expect("Failed to spawn second thread");

        println!(
            "COAP server thread spawned as {:?} ({:?}), status {:?}",
            secondthread.pid(),
            secondthread.pid().get_name(),
            secondthread.status()
        );

        let shellthread = threadscope
            .spawn(
                shellthread_stacklock.as_mut(),
                &mut shellthread_mainclosure,
                cstr!("shellthread"),
                (riot_sys::THREAD_PRIORITY_MAIN - 1) as _,
                (riot_sys::THREAD_CREATE_STACKTEST) as _,
            )
            .expect("Failed to spawn shell thread");

        println!(
            "Shell thread spawned as {:?} ({:?}), status {:?}",
            shellthread.pid(),
            shellthread.pid().get_name(),
            shellthread.status()
        );

        loop {
            thread::sleep();
        }
    });
    unreachable!();
}


