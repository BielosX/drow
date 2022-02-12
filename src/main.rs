use std::{env, mem};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Read};

#[repr(C, packed)]
struct Elf64Header {
    e_ident: [u8;16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64
}


impl Display for Elf64Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let elf_type: HashMap<u16, &str> = [
            (0, "No file type"),
            (1, "Relocatable file"),
            (2, "Executable file"),
            (3, "Shared object type"),
            (4, "Core file")
        ].iter().cloned().collect();
        f.write_str(format!("File type: {}\n", elf_type.get(&self.e_type).unwrap_or(&"Other")).as_str())?;
        f.write_str(format!("Machine: {:#02X}\n", self.e_machine).as_str());
        f.write_str(format!("Version: {:#02X}\n", self.e_version).as_str());
        f.write_str(format!("Entry point address: {:#X}", self.e_entry).as_str())
    }
}

fn check_file_ident(header: &Elf64Header) -> Result<(), String> {
    let mag = &header.e_ident[0..4];
    if mag[0] == 0x7F && mag[1] == 'E' as u8 && mag[2] == 'L' as u8 && mag[3] == 'F' as u8 {
        println!("ELF file detected");
        Ok(())
    } else {
        Result::Err(format!("Not an ELF file. {:#02X} {:#02X} {:#02X} {:#02X}", mag[0], mag[1], mag[2], mag[3]))
    }
}

fn check_class(header: &Elf64Header) -> Result<(), String> {
    let mag = &header.e_ident[4..5];
    if mag[0] == 2 {
        println!("ELF64 detected");
        Ok(())
    } else {
        Result::Err(format!("ELF64 required, found: {:#02X}", mag[0]))
    }
}

fn check_endian(header: &Elf64Header) -> Result<(), String> {
    let mag = &header.e_ident[4..5];
    if mag[0] == 2 {
        println!("Little endian encoding detected");
        Ok(())
    } else {
        Result::Err(format!("Little Endian required, found: {:#02X}", mag[0]))
    }
}

fn check_machine(header: &Elf64Header) -> Result<(), String> {
    if header.e_machine == 0x3E {
        println!("AMD64 detected");
        Ok(())
    } else {
        Result::Err(format!("AMD64 expected, found: {:#02X}", header.e_machine))
    }
}

fn check_header(header: &Elf64Header) -> Result<(), String> {
    check_file_ident(header)?;
    check_class(header)?;
    check_endian(header)?;
    check_machine(header)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Path argument should be provided");
        std::process::exit(-1);
    }
    let file_path = &args[1];
    let elf_file = File::open(file_path).expect("Unable to open elf file");
    let mut reader = BufReader::new(elf_file);
    let mut header_buffer: Vec<u8> = Vec::new();
    header_buffer.resize(mem::size_of::<Elf64Header>(), 0);
    reader.read_exact(&mut header_buffer);
    let header: Elf64Header = unsafe {
        std::ptr::read_unaligned(header_buffer.as_ptr() as *const _)
    };
    check_header(&header).unwrap();
    print!("{}\n", header);
}
