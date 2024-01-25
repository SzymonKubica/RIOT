use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use riot_wrappers::cstr::cstr;
use riot_wrappers::{gcoap, gnrc, mutex::Mutex, riot_sys, stdio::println, thread, ztimer};

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

    let mut static_resource_handler = static_application_tree();
    let mut static_resource_listener = gcoap::SingleHandlerListener::new(
        cstr!("/"),
        riot_sys::COAP_GET,
        &mut static_resource_handler,
    );

    gcoap::scope(|greg| {
        // Endpoint handlers are registered here.
        greg.register(&mut console_write_listener);
        greg.register(&mut riot_board_listener);
        greg.register(&mut static_resource_listener);

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

/// Defines the static resources available on the server
pub fn static_application_tree() -> impl coap_handler::Handler {
    use coap_handler_implementations::{new_dispatcher, HandlerBuilder, ReportingHandlerBuilder};

    use coap_handler::Attribute::*;

    let handler =
        new_dispatcher().at_with_attributes(&[], &[Ct(0), Title("Landing page")], WELCOME);

    handler.with_wkc()
}

pub static WELCOME: SimpleRendered<&str> = SimpleRendered("Hello CoAP");

struct RiotBoardHandler;
impl coap_handler::Handler for RiotBoardHandler {
    type RequestData = u8;

    fn extract_request_data(&mut self, request: &impl ReadableMessage) -> Self::RequestData {
        if request.code().into() != coap_numbers::code::GET {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }
        return coap_numbers::code::VALID;
    }

    fn estimate_length(&mut self, _request: &Self::RequestData) -> usize {
        1
    }

    fn build_response(
        &mut self,
        response: &mut impl MutableWritableMessage,
        request: Self::RequestData,
    ) {
        response.set_code(request.try_into().map_err(|_| ()).unwrap());
        println!("Request for the riot board name received");
        let board_name = core::str::from_utf8(riot_sys::RIOT_BOARD)
            .expect("Oddly named board crashed CoAP stack");
        response.set_payload(board_name.as_bytes());
    }
}

pub fn handle_riot_board() -> impl coap_handler::Handler {
    RiotBoardHandler
}

struct ConsoleWrite;
impl coap_handler::Handler for ConsoleWrite {
    type RequestData = u8;

    fn extract_request_data(&mut self, request: &impl ReadableMessage) -> Self::RequestData {
        if request.code().into() != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }
        match core::str::from_utf8(request.payload()) {
            Ok(s) => {
                println!("{}", s);
                coap_numbers::code::CHANGED
            }
            _ => coap_numbers::code::BAD_REQUEST,
        }
    }

    fn estimate_length(&mut self, _request: &Self::RequestData) -> usize {
        1
    }

    fn build_response(
        &mut self,
        response: &mut impl MutableWritableMessage,
        request: Self::RequestData,
    ) {
        response.set_code(request.try_into().map_err(|_| ()).unwrap());
        let result = "Success";
        response.set_payload(result.as_bytes());
    }
}

pub fn handle_console_write() -> impl coap_handler::Handler {
    ConsoleWrite
}
