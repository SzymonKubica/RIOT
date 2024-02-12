use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use riot_wrappers::cstr::cstr;
use riot_wrappers::{
    coap_handler::GcoapHandler, gcoap, gcoap::SingleHandlerListener, gnrc, mutex::Mutex, riot_sys,
    stdio::println, thread, ztimer, gpio,
};

use crate::handlers::{
    execute_fc_on_coap_pkt, execute_rbpf_on_coap_pkt, handle_benchmark, handle_bytecode_load,
    handle_console_write_request, handle_riot_board_query, handle_suit_pull_request,
};

pub fn gcoap_server_main(_countdown: &Mutex<u32>) -> Result<(), ()> {





    // Each endpoint needs a request handler defined as its own struct implemneting
    // the Handler trait. Then we need to initialise a listener for that endpoint
    // and add it as a resource in the gcoap scope.

    // Example handlers
    let mut console_write_handler = GcoapHandler(handle_console_write_request());
    let mut riot_board_handler = GcoapHandler(handle_riot_board_query());

    // Handlers for executing benchmarks and initiating SUIT firmware fetch.
    let mut benchmark_handler = GcoapHandler(handle_benchmark());
    let mut suit_pull_handler = GcoapHandler(handle_suit_pull_request());

    // Custom handlers operating on the packet bytes directly. Used for executing
    // rBPf and FemtoContainer VMs with access to the packet data.
    let mut rbpf_handler = execute_rbpf_on_coap_pkt();
    let mut femtocontainer_handler = execute_fc_on_coap_pkt();

    let mut console_write_listener = SingleHandlerListener::new(
        cstr!("/console/write"),
        riot_sys::COAP_POST,
        &mut console_write_handler,
    );

    let mut riot_board_listener = SingleHandlerListener::new(
        cstr!("/riot/board"),
        riot_sys::COAP_GET,
        &mut riot_board_handler,
    );

    let mut rbpf_listener =
        SingleHandlerListener::new(cstr!("/rbpf/exec"), riot_sys::COAP_POST, &mut rbpf_handler);

    let mut femtocontainer_listener = SingleHandlerListener::new(
        cstr!("/femto-container/exec"),
        riot_sys::COAP_POST,
        &mut femtocontainer_handler,
    );

    let mut benchmark_listener = SingleHandlerListener::new(
        cstr!("/benchmark"),
        riot_sys::COAP_POST,
        &mut benchmark_handler,
    );

    let mut suit_pull_listener = SingleHandlerListener::new(
        cstr!("/suit/pull"),
        riot_sys::COAP_POST,
        &mut suit_pull_handler,
    );

    gcoap::scope(|greg| {
        // Endpoint handlers are registered here.
        greg.register(&mut console_write_listener);
        greg.register(&mut riot_board_listener);
        greg.register(&mut rbpf_listener);
        greg.register(&mut femtocontainer_listener);
        greg.register(&mut benchmark_listener);
        greg.register(&mut suit_pull_listener);

        println!(
            "CoAP server ready; waiting for interfaces to settle before reporting addresses..."
        );

        let sectimer = ztimer::Clock::sec();
        sectimer.sleep_ticks(2);
        print_network_interfaces();

        // Sending main thread to sleep; can't return or the Gcoap handler would need to be
        // deregistered (which it can't).
        loop {
            thread::sleep();
        }
    });

    Ok(())
}

fn print_network_interfaces() {
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
}
