// Copyright (C) 2020 Christian Amsüss
//
// This file is subject to the terms and conditions of the GNU Lesser
// General Public License v2.1. See the file LICENSE in the top level
// directory for more details.
#![no_std]

use riot_wrappers::riot_main;
use riot_wrappers::println;
use riot_wrappers::riot_sys::malloc;

extern crate rust_riotmodules;
extern crate rbpf;

riot_main!(main);

fn main() {
    let prog = &[
         0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Load mem from mbuff into R1.
         0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
         0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // exit
     ];
     let mem = &mut [
         0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd
     ];

     // Just for the example we create our metadata buffer from scratch, and we store the
     // pointers to packet data start and end in it.
     let mut mbuff = [0u8; 32];
     unsafe {
         let mut data     = mbuff.as_ptr().offset(8)  as *mut u64;
         let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
         *data     = mem.as_ptr() as u64;
         *data_end = mem.as_ptr() as u64 + mem.len() as u64;
     }

     // Instantiate a VM.
     let mut vm = rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();

     // Provide both a reference to the packet data, and to the metadata buffer.
     let res = vm.execute_program(mem, &mut mbuff).unwrap();
     assert_eq!(res, 0x2211);
     println!("res: 0x{:x}", res);
}

