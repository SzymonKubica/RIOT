use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use coap_handler_implementations::SimpleRendered;
use coap_message::{MessageOption, MutableWritableMessage, ReadableMessage};
use core::convert::TryInto;
use core::fmt;
use riot_wrappers::coap_message::ResponseMessage;
use riot_wrappers::gcoap::PacketBuffer;
use riot_wrappers::{cstr::cstr, stdio::println, ztimer::Clock};
use riot_wrappers::{mutex::Mutex, thread, ztimer};

use crate::middleware;
use crate::rbpf;
use crate::rbpf::helpers;
use crate::vm::{FemtoContainerVm, RbpfVm, VirtualMachine};
use serde::{Deserialize, Serialize};
// The riot_sys reimported through the wrappers doesn't seem to work.
use riot_sys;

/// The handler expects to receive a request that contains a vm_target
/// and the SUIT storage location from where to load the program.
#[derive(Deserialize)]
struct RequestData {
    pub vm_target: VmTarget,
    pub suit_location: usize,
}

#[derive(Deserialize)]
enum VmTarget {
    Rbpf,
    FemtoContainer,
}

/// Executes a chosen eBPF VM while passing in a pointer to the incoming packet
/// to the executed program. The eBPF script can access the CoAP packet data.
struct VMExecutionOnCoapPktHandler {
    execution_time: u32,
    result: i64,
}

impl riot_wrappers::gcoap::Handler for VMExecutionOnCoapPktHandler {
    fn handle(&mut self, pkt: &mut PacketBuffer) -> isize {
        let request_data = self.handle_request(pkt);
        let mut lengthwrapped = ResponseMessage::new(pkt);
        self.build_response(&mut lengthwrapped, request_data);
        lengthwrapped.finish()
    }
}

impl VMExecutionOnCoapPktHandler {
    fn handle_request(&mut self, request: &mut PacketBuffer) -> u8 {
        let preprocessing_result = preprocess_request(request);
        let Ok(request_data) = preprocessing_result else {
            let Err(code) = preprocessing_result;
            return code;
        };

        // The SUIT ram storage for the program is 2048 bytes large so we won't
        // be able to load larger images. Hence 2048 byte buffer is sufficient
        let mut program_buffer: [u8; 2048] = [0; 2048];
        let location = format!(".ram.{0}\0", request_data.suit_location);
        let program = Self::read_program_from_suit_storage(&mut program_buffer, &location);

        println!(
            "Loaded program bytecode from SUIT storage location {}, program length: {}",
            location,
            program.len()
        );

        // Dynamically dispatch between the two different VM implementations
        // depending on the request data.
        let vm: Box<dyn VirtualMachine> = match request_data.vm_target {
            VmTarget::Rbpf => Box::new(RbpfVm::new(Vec::from(middleware::ALL_HELPERS))),
            VmTarget::FemtoContainer => Box::new(FemtoContainerVm {}),
        };

        self.execution_time = vm.execute_on_coap_pkt(&program, request, &mut self.result);

        coap_numbers::code::CHANGED
    }

    fn build_response(&mut self, response: &mut impl MutableWritableMessage, request: u8) {
        format_execution_response(self.execution_time, self.result, response, request);
    }
}

pub fn execute_vm_on_coap_pkt() -> impl riot_wrappers::gcoap::Handler {
    VMExecutionOnCoapPktHandler {
        execution_time: 0,
        result: 0,
    }
}

/// Executes a chosen eBPF VM while passing in a pointer to the incoming packet
/// to the executed program. The eBPF script can access the CoAP packet data.
struct VMExecutionNoDataHandler {
    execution_time: u32,
    result: i64,
}

impl riot_wrappers::gcoap::Handler for VMExecutionNoDataHandler {
    fn handle(&mut self, pkt: &mut PacketBuffer) -> isize {
        let request_data = self.handle_request(pkt);
        let mut lengthwrapped = ResponseMessage::new(pkt);
        self.build_response(&mut lengthwrapped, request_data);
        lengthwrapped.finish()
    }
}

impl VMExecutionNoDataHandler {
    fn handle_request(&mut self, request: &mut PacketBuffer) -> u8 {
        let preprocessing_result = preprocess_request(request);
        let Ok(request_data) = preprocessing_result else {
            let Err(code) = preprocessing_result;
            return code;
        };

        // The SUIT ram storage for the program is 2048 bytes large so we won't
        // be able to load larger images. Hence 2048 byte buffer is sufficient
        let mut program_buffer: [u8; 2048] = [0; 2048];
        let location = format!(".ram.{0}\0", request_data.suit_location);
        let program = Self::read_program_from_suit_storage(&mut program_buffer, &location);

        println!(
            "Loaded program bytecode from SUIT storage location {}, program length: {}",
            location,
            program.len()
        );

        // Dynamically dispatch between the two different VM implementations
        // depending on the request data.
        let vm: Box<dyn VirtualMachine> = match request_data.vm_target {
            VmTarget::Rbpf => Box::new(RbpfVm::new(Vec::from(middleware::ALL_HELPERS))),
            VmTarget::FemtoContainer => Box::new(FemtoContainerVm {}),
        };

        self.execution_time = vm.execute(&program, &mut self.result);

        coap_numbers::code::CHANGED
    }

    fn build_response(&mut self, response: &mut impl MutableWritableMessage, request: u8) {
        format_execution_response(self.execution_time, self.result, response, request);
    }
}

pub fn execute_vm_no_data() -> impl riot_wrappers::gcoap::Handler {
    VMExecutionNoDataHandler {
        execution_time: 0,
        result: 0,
    }
}

/* Common utility functions for the handlers */

/// Reads from the given suit storage into the provided program buffer
fn read_program_from_suit_storage<'a>(program_buffer: &'a mut [u8], location: &str) -> &'a [u8] {
    let mut length = 0;
    unsafe {
        let buffer_ptr = program_buffer.as_mut_ptr();
        let location_ptr = location.as_ptr() as *const char;
        length = load_bytes_from_suit_storage(buffer_ptr, location_ptr);
    };
    &program_buffer[..(length as usize)]
}

extern "C" {
    /// Responsible for loading the bytecode from the SUIT ram storage.
    /// The application bytes are written into the buffer.
    fn load_bytes_from_suit_storage(buffer: *mut u8, location: *const char) -> u32;
}

fn format_execution_response(
    execution_time: u32,
    result: i64,
    response: &mut impl MutableWritableMessage,
    request: u8,
) {
    response.set_code(request.try_into().map_err(|_| ()).unwrap());
    let resp = format!(
        "{{\"execution_time\": {}, \"result\": {}}}",
        execution_time, result
    );
    response.set_payload(resp.as_bytes());
}

fn preprocess_request(request: &mut PacketBuffer) -> Result<RequestData, u8> {
    if request.code() as u8 != coap_numbers::code::POST {
        return Err(coap_numbers::code::METHOD_NOT_ALLOWED);
    }

    // Request payload determines from which SUIT storage slot we are
    // reading the bytecode.
    let Ok(s) = core::str::from_utf8(request.payload()) else {
        return Err(coap_numbers::code::BAD_REQUEST);
    };

    println!("Request payload received: {}", s);
    let Ok((request_data, length)): Result<(RequestData, usize), _> = serde_json_core::from_str(s)
    else {
        return Err(coap_numbers::code::BAD_REQUEST);
    };

    Ok(request_data)
}
