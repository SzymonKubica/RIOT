use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use riot_wrappers::cstr::cstr;
use riot_wrappers::{gcoap, gnrc, mutex::Mutex, riot_sys, stdio::println, thread, ztimer};

use crate::handlers::handle_benchmark;
use crate::handlers::handle_bytecode_load;
use crate::handlers::handle_console_write;
use crate::handlers::handle_suit_pull;
use crate::handlers::{handle_femtocontainer_execution, handle_riot_board};

pub fn gcoap_server_main(_countdown: &Mutex<u32>) -> Result<(), ()> {
    // Each endpoint needs a request handler defined as its own struct implemneting
    // the Handler trait. Then we need to initialise a listener for that endpoint
    // and add it as a resource in the gcoap scope.
    let mut console_write_handler =
        riot_wrappers::coap_handler::GcoapHandler(handle_console_write());
    let mut console_write_listener = gcoap::SingleHandlerListener::new(
        cstr!("/console/write"),
        riot_sys::COAP_POST,
        &mut console_write_handler,
    );

    let mut riot_board_handler = riot_wrappers::coap_handler::GcoapHandler(handle_riot_board());
    let mut riot_board_listener = gcoap::SingleHandlerListener::new(
        cstr!("/riot/board"),
        riot_sys::COAP_GET,
        &mut riot_board_handler,
    );

    let mut bytecode_handler = riot_wrappers::coap_handler::GcoapHandler(handle_bytecode_load());
    let mut bytecode_listener = gcoap::SingleHandlerListener::new(
        cstr!("/rbpf/exec"),
        riot_sys::COAP_POST,
        &mut bytecode_handler,
    );

    let mut femtocontainer_handler =
        riot_wrappers::coap_handler::GcoapHandler(handle_femtocontainer_execution());
    let mut femtocontainer_listener = gcoap::SingleHandlerListener::new(
        cstr!("/bpf/exec"),
        riot_sys::COAP_POST,
        &mut femtocontainer_handler,
    );

    let mut bench_handler = riot_wrappers::coap_handler::GcoapHandler(handle_benchmark());
    let mut bench_listener = gcoap::SingleHandlerListener::new(
        cstr!("/benchmark"),
        riot_sys::COAP_POST,
        &mut bench_handler,
    );

    let mut suit_pull_handler = riot_wrappers::coap_handler::GcoapHandler(handle_suit_pull());
    let mut suit_pull_listener = gcoap::SingleHandlerListener::new(
        cstr!("/suit-pull"),
        riot_sys::COAP_POST,
        &mut suit_pull_handler,
    );

    gcoap::scope(|greg| {
        // Endpoint handlers are registered here.
        greg.register(&mut console_write_listener);
        greg.register(&mut riot_board_listener);
        greg.register(&mut bytecode_listener);
        greg.register(&mut femtocontainer_listener);
        greg.register(&mut bench_listener);
        greg.register(&mut suit_pull_listener);

        println!(
            "CoAP server ready; waiting for interfaces to settle before reporting addresses..."
        );

        let sectimer = ztimer::Clock::sec();
        sectimer.sleep_ticks(2);

        for netif in gnrc::Netif::all() {
            println!(
                "Active interface from PID {:?} ({:?})",
                netif.pid(),
                netif.pid().get_name().unwrap_or("unnamed")
            );
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
        loop {
            thread::sleep();
        }
    });

    Ok(())
}
