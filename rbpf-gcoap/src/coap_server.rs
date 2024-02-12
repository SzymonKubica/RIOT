use coap_handler;
use core::convert::TryInto;
use riot_wrappers::coap_message;
use riot_wrappers::cstr::cstr;
use riot_wrappers::{gcoap, gnrc, mutex::Mutex, riot_sys, stdio::println, thread, ztimer};

use crate::handlers::handle_femtocontainer_execution;
use crate::handlers::handle_suit_pull;
use crate::handlers::{handle_benchmark, ConsoleWrite, SuitPullHandler};
use crate::handlers::{handle_bytecode_load, FemtoContainerCoAPExecutor, RbpfCoapHandler};

pub fn gcoap_server_main(_countdown: &Mutex<u32>) -> Result<(), ()> {
    // Each endpoint needs a request handler defined as its own struct implemneting
    // the Handler trait. Then we need to initialise a listener for that endpoint
    // and add it as a resource in the gcoap scope.
    let mut console_write_handler =
        coap_handler::GcoapHandler(&mut ConsoleWrite as &mut dyn coap_handler::Handler);

    let mut listeners = [
        create_post_listener("/console/write", &mut console_write_handler),
        create_get_listener(
            "/riot/board",
            &mut riot_wrappers::coap_handler::GcoapHandler(
                &mut RiotBoardHandler as &mut dyn coap_handler::Handler,
            ),
        ),
        create_post_listener(
            "/rbpf/exec",
            &mut RbpfCoapHandler {} as &mut dyn gcoap::Handler,
        ),
        create_post_listener(
            "/femto-container/exec",
            &mut FemtoContainerCoAPExecutor {} as &mut gcoap::Handler,
        ),
        create_post_listener(
            "/benchmark",
            &mut riot_wrappers::coap_handler::GcoapHandler(
                handle_benchmark() as &mut dyn coap_handler::Handler
            ),
        ),
        create_post_listener(
            "/suit/pull",
            &mut riot_wrappers::coap_handler::GcoapHandler(
                &mut SuitPullHandler {} as &mut dyn coap_handler::Handler
            ),
        ),
    ];

    gcoap::scope(|greg| {
        // Endpoint handlers are registered here.
        for listener in &mut listeners {
            greg.register(listener);
        }

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

fn create_get_listener<'a, H>(
    path: &'a str,
    handler: &'a mut H,
) -> gcoap::SingleHandlerListener<'a, H>
where
    H: 'a + gcoap::Handler,
{
    gcoap::SingleHandlerListener::new(cstr!(path), riot_sys::COAP_GET, handler)
}

fn create_post_listener<'a, H>(
    path: &'a str,
    handler: &'a mut H,
) -> gcoap::SingleHandlerListener<'a, H>
where
    H: 'a + gcoap::Handler,
{
    gcoap::SingleHandlerListener::new(cstr!(path), riot_sys::COAP_POST, handler)
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
