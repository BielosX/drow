use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::{env, mem};

use libc::{c_char, perror};

use crate::elf::*;
use crate::loader::Elf64Loader;

mod elf;
mod loader;
mod printer;
mod syscall;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Path argument should be provided");
        std::process::exit(-1);
    }
    let file_path = &args[1];
    let elf_file = File::open(file_path).expect("Unable to open elf file");
    let mut reader = BufReader::new(elf_file);
    let elf_metadata: Elf64Metadata = Elf64Metadata::load(&mut reader).unwrap();
    printer::print(&elf_metadata, &mut reader);
    Elf64Loader::load(file_path, &elf_metadata);
}
