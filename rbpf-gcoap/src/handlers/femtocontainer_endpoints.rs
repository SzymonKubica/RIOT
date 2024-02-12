use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use core::ffi::c_void;
use core::fmt;
use riot_wrappers::coap_message::ResponseMessage;
use riot_wrappers::gcoap::PacketBuffer;
use riot_wrappers::{cstr::cstr, stdio::println, ztimer::Clock};
use riot_wrappers::gcoap;

use crate::rbpf;
use crate::rbpf::helpers;
// The riot_sys reimported through the wrappers doesn't seem to work.
use riot_sys;

pub struct FemtoContainerExecutor {}

const PACKET_TEMPLATE_SIZE: usize = 54;

impl coap_handler::Handler for FemtoContainerExecutor {
    type RequestData = u8;

    fn extract_request_data(&mut self, request: &impl ReadableMessage) -> Self::RequestData {
        extern "C" {
            /// Responsible for loading the bytecode from the SUIT ram storage.
            /// The application bytes are written into the buffer.
            fn execute_femtocontainer_vm(
                payload: *const u8,
                payload_len: usize,
                location: *const char,
            ) -> u32;
        }

        if request.code().into() != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }

        // Request payload determines from which SUIT storage slot we are
        // reading the bytecode.
        let Ok(s) = core::str::from_utf8(request.payload()) else {
            return coap_numbers::code::BAD_REQUEST;
        };

        println!("Request payload received: {}", s);

        let mut location = format!(".ram.{s}\0");

        let checksum_message = "abcdef\
            AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc\
            d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3\
            QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs\
            4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT\
            tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n\
            byNy4yqxu7";

        let message_bytes = checksum_message.as_bytes();

        let mut execution_time = 0;
        unsafe {
            execution_time = execute_femtocontainer_vm(
                message_bytes.as_ptr(),
                message_bytes.len(),
                location.as_ptr() as *const char,
            );
        }

        coap_numbers::code::CHANGED
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
        response.set_payload(b"Success");
    }
}

// Responsible for executing the femtocontainer VM given a CoAP packet.
pub struct FemtoContainerCoAPExecutor {}

impl FemtoContainerCoAPExecutor {
    fn extract_request_data(&mut self, request: &mut PacketBuffer) -> u8 {
        extern "C" {
            fn execute_femtocontainer_vm_coap_packet(
                pkt: *mut PacketBuffer,
                location: *const char,
            ) -> u32;
        }

        if request.code() as u8 != coap_numbers::code::POST {
            return coap_numbers::code::METHOD_NOT_ALLOWED;
        }

        // Request payload determines from which SUIT storage slot we are
        // reading the bytecode.
        let Ok(s) = core::str::from_utf8(request.payload()) else {
            return coap_numbers::code::BAD_REQUEST;
        };

        println!("Request payload received: {}", s);

        let mut location = format!(".ram.{s}\0");

        unsafe {
            let execution_time = execute_femtocontainer_vm_coap_packet(
                request as *mut PacketBuffer,
                location.as_ptr() as *const char,
            );
        }

        coap_numbers::code::CHANGED
    }

    fn estimate_length(&mut self, _request: &u8) -> usize {
        1
    }

    fn build_response(&mut self, response: &mut impl MutableWritableMessage, request: u8) {
        response.set_code(request.try_into().map_err(|_| ()).unwrap());
        response.set_payload(b"Success");
    }
}

impl riot_wrappers::gcoap::Handler for FemtoContainerCoAPExecutor {
    fn handle(&mut self, pkt: &mut PacketBuffer) -> isize {
        let request_data = self.extract_request_data(pkt);
        let mut lengthwrapped = ResponseMessage::new(pkt);
        self.build_response(&mut lengthwrapped, request_data);
        lengthwrapped.finish()
    }
}

