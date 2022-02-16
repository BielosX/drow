mod syscall;

use libc::{c_char, perror};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::{env, mem};

const IDENT_SIZE: usize = 16;

#[repr(C)]
struct Elf64Header {
    e_ident: [u8; IDENT_SIZE],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_program_header_offset: u64,
    e_section_header_offset: u64,
    e_flags: u32,
    e_elf_header_size: u16,
    e_program_header_entry_size: u16,
    e_program_header_entries: u16,
    e_section_header_entry_size: u16,
    e_section_header_entries: u16,
    e_section_name_string_table_index: u16,
}

#[repr(C)]
struct Elf64ProgramHeader {
    p_type: u32,
    p_offset: u64,
    p_virtual_address: u64,
    p_physical_address: u64,
    p_file_size: u64,
    p_memory_size: u64,
    p_align: u64,
}

const ELF64_SECTION_HEADER_UNUSED: u32 = 0;
const ELF64_SECTION_HEADER_STRING_TABLE: u32 = 3;

#[repr(C)]
struct Elf64SectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_virtual_address: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_address_align: u64,
    sh_entry_size: u64,
}

impl Display for Elf64SectionHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let section_type: HashMap<u32, &str> = [
            (0, "Unused"),
            (1, "Program Information"),
            (2, "Linker symbol table"),
            (3, "String table"),
            (4, "'Rela' type relocation entries"),
            (5, "Symbol hash table"),
            (6, "Dynamic linking tables"),
            (7, "Note information"),
            (8, "Uninitialized space"),
            (9, "'Rel' type allocation entries"),
            (10, "Reserved"),
            (11, "Dynamic loader symbol table"),
        ]
        .iter()
        .cloned()
        .collect();
        f.write_str("|")?;
        f.write_str(
            format!(
                "Type: {}",
                section_type.get(&self.sh_type).unwrap_or(&"Other")
            )
            .as_str(),
        )?;
        f.write_str(format!("|Name Index: {}", self.sh_name).as_str())?;
        f.write_str(format!("|Virtual Address: {:#X}", self.sh_virtual_address).as_str())?;
        f.write_str(format!("|Offset: {}", self.sh_offset).as_str())?;
        f.write_str("|\n")
    }
}

impl Display for Elf64ProgramHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let segment_type: HashMap<u32, &str> = [
            (0, "Unused"),
            (1, "Loadable"),
            (2, "Dynamic linking tables"),
            (3, "Program interpreter path"),
            (4, "Note sections"),
            (5, "Reserved"),
            (6, "Program Header Table"),
        ]
        .iter()
        .cloned()
        .collect();
        f.write_str("|")?;
        f.write_str(
            format!(
                "Type: {}",
                segment_type.get(&self.p_type).unwrap_or(&"Other")
            )
            .as_str(),
        )?;
        f.write_str(format!("|Offset: {}", self.p_offset).as_str())?;
        f.write_str(format!("|Virtual Address: {:#X}", self.p_virtual_address).as_str())?;
        f.write_str(format!("|File Size: {}", self.p_file_size).as_str())?;
        f.write_str(format!("|Memory Size: {}", self.p_memory_size).as_str())?;
        f.write_str("|\n")
    }
}

impl Display for Elf64Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let elf_type: HashMap<u16, &str> = [
            (0, "No file type"),
            (1, "Relocatable file"),
            (2, "Executable file"),
            (3, "Shared object type"),
            (4, "Core file"),
        ]
        .iter()
        .cloned()
        .collect();
        let mut magic = String::new();
        for x in 0..IDENT_SIZE {
            if x == 0 {
                magic.push_str(format!("{:#02X}", self.e_ident[x]).as_str());
            } else {
                magic.push_str(format!(" {:#02X}", self.e_ident[x]).as_str());
            }
        }
        f.write_str(format!("Magic: {}\n", magic).as_str())?;
        f.write_str(
            format!(
                "File type: {}\n",
                elf_type.get(&self.e_type).unwrap_or(&"Other")
            )
            .as_str(),
        )?;
        f.write_str(format!("Machine: {:#02X}\n", self.e_machine).as_str())?;
        f.write_str(format!("Version: {:#02X}\n", self.e_version).as_str())?;
        f.write_str(format!("Entry point address: {:#X}\n", self.e_entry).as_str())?;
        f.write_str(
            format!(
                "Program header table offset: {}\n",
                self.e_program_header_offset
            )
            .as_str(),
        )?;
        f.write_str(
            format!(
                "Section header table offset: {}\n",
                self.e_section_header_offset
            )
            .as_str(),
        )?;
        f.write_str(
            format!(
                "Program header entries: {}\n",
                self.e_program_header_entries
            )
            .as_str(),
        )?;
        f.write_str(
            format!(
                "Section header entries: {}\n",
                self.e_section_header_entries
            )
            .as_str(),
        )?;
        f.write_str(
            format!(
                "Section name string table: {}\n",
                self.e_section_name_string_table_index
            )
            .as_str(),
        )
    }
}

fn check_file_ident(header: &Elf64Header) -> Result<(), String> {
    let mag = &header.e_ident[0..4];
    if mag[0] == 0x7F && mag[1] == 'E' as u8 && mag[2] == 'L' as u8 && mag[3] == 'F' as u8 {
        println!("ELF file detected");
        Ok(())
    } else {
        Result::Err(format!(
            "Not an ELF file. {:#02X} {:#02X} {:#02X} {:#02X}",
            mag[0], mag[1], mag[2], mag[3]
        ))
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

fn get_string_tables_content<T: Read + Seek>(
    section_headers: &Vec<Elf64SectionHeader>,
    reader: &mut T,
) -> HashMap<u64, Vec<u8>> {
    let mut result = HashMap::new();
    let string_table_headers = section_headers
        .iter()
        .filter(|t| t.sh_type == ELF64_SECTION_HEADER_STRING_TABLE);
    for entry in string_table_headers {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.resize(entry.sh_size as usize, 0);
        reader
            .seek(SeekFrom::Start(entry.sh_offset))
            .expect("Unable to change position");
        reader
            .read_exact(&mut buffer)
            .expect("Unable to read string table content");
        result.insert(entry.sh_offset, buffer);
    }
    result
}

fn convert_string_tables_content(string_tables: &HashMap<u64, Vec<u8>>) -> HashMap<u64, Vec<&str>> {
    let mut result = HashMap::new();
    for (key, value) in string_tables.iter() {
        let mut strings = Vec::new();
        for part in value.split(|x| *x == 0) {
            strings.push(std::str::from_utf8(part).unwrap());
        }
        result.insert(*key, strings);
    }
    result
}

fn load_program_headers<T: Read + Seek>(
    header: &Elf64Header,
    reader: &mut T,
) -> Vec<Elf64ProgramHeader> {
    reader
        .seek(SeekFrom::Start(header.e_program_header_offset))
        .expect("Unable to change position");
    let mut program_headers: Vec<Elf64ProgramHeader> = Vec::new();
    for _ in 0..header.e_program_header_entries {
        let mut program_header_buffer: Vec<u8> = Vec::new();
        program_header_buffer.resize(mem::size_of::<Elf64ProgramHeader>(), 0);
        reader
            .read_exact(&mut program_header_buffer)
            .expect("Read error");
        let program_header: Elf64ProgramHeader =
            unsafe { std::ptr::read_unaligned(program_header_buffer.as_ptr() as *const _) };
        program_headers.push(program_header);
    }
    program_headers
}

fn load_elf_header<T: Read>(reader: &mut T) -> Elf64Header {
    let mut header_buffer: Vec<u8> = Vec::new();
    header_buffer.resize(mem::size_of::<Elf64Header>(), 0);
    reader.read_exact(&mut header_buffer).expect("Read error");
    let header: Elf64Header =
        unsafe { std::ptr::read_unaligned(header_buffer.as_ptr() as *const _) };
    header
}

fn load_section_headers<T: Read + Seek>(
    header: &Elf64Header,
    reader: &mut T,
) -> Vec<Elf64SectionHeader> {
    reader
        .seek(SeekFrom::Start(header.e_section_header_offset))
        .expect("Unable to change position");
    let mut section_headers: Vec<Elf64SectionHeader> = Vec::new();
    for _ in 0..header.e_section_header_entries {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.resize(mem::size_of::<Elf64SectionHeader>(), 0);
        reader.read_exact(&mut buffer).expect("Read error");
        let section_header: Elf64SectionHeader =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };
        section_headers.push(section_header);
    }
    section_headers
}

fn string_length(string: &[u8]) -> usize {
    let mut index = 0;
    while string[index] != 0 {
        index += 1;
    }
    return index + 1;
}

struct ProgramStack {
    address: *const libc::c_void,
    last_address: *const libc::c_void,
}

impl ProgramStack {
    fn allocate(size: libc::size_t) -> Option<ProgramStack> {
        let mut result = Option::None;
        unsafe {
            let ptr: *const libc::c_void = syscall::mmap(
                0 as *const libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                0,
                0,
            );
            if ptr != libc::MAP_FAILED {
                println!("Allocated pointer: {:#X}", ptr as usize);
                result = Option::Some(ProgramStack {
                    address: ptr,
                    last_address: (ptr as usize + (size - 1)) as *const libc::c_void,
                });
            } else {
                println!("Mmap failed");
                unsafe {
                    let error_location = libc::__errno_location();
                    perror(error_location as *const libc::c_char);
                };
            }
        }
        result
    }
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
    let header = load_elf_header(&mut reader);
    check_header(&header).unwrap();
    print!("{}\n", header);
    let program_headers = load_program_headers(&header, &mut reader);
    println!("Program headers");
    for header in program_headers.iter() {
        println!("{}", header);
    }
    let section_headers = load_section_headers(&header, &mut reader);
    let string_tables_content = get_string_tables_content(&section_headers, &mut reader);
    let string_tables_content_converted = convert_string_tables_content(&string_tables_content);
    for (key, value) in string_tables_content_converted.iter() {
        println!("String table at {} content:", key);
        for entry in value.iter() {
            println!("{}", entry);
        }
    }
    println!("Section headers");
    let section_names = section_headers
        .get(header.e_section_name_string_table_index as usize)
        .unwrap();
    let section_names_table = string_tables_content.get(&section_names.sh_offset).unwrap();
    for header in section_headers.iter() {
        let idx = header.sh_name as usize;
        let length = string_length(&section_names_table[idx..]);
        let end_idx = idx + length;
        let name = std::str::from_utf8(&section_names_table[idx..end_idx]).unwrap();
        println!("Section name: {}, header: {}", name, header);
    }
    let file_descriptor =
        unsafe { syscall::open(file_path.as_ptr() as *const c_char, libc::O_RDONLY) };
    if file_descriptor < 0 {
        eprintln!("Unable to open file");
        std::process::exit(-1);
    } else {
        println!("File descriptor: {}", file_descriptor);
    }
    let mut virtual_address: Vec<*const libc::c_void> = Vec::new();
    let program_info: Vec<Elf64SectionHeader> = section_headers
        .into_iter()
        .filter(|h| h.sh_type == 1)
        .collect();
    let offset = 0x20000;
    for info in program_info {
        let virtual_ptr = (info.sh_virtual_address + offset) as *const libc::c_void;
        let ptr: *const libc::c_void = unsafe {
            syscall::mmap(
                virtual_ptr,
                info.sh_size as libc::size_t,
                libc::PROT_EXEC | libc::PROT_READ,
                libc::MAP_FIXED | libc::MAP_SHARED,
                file_descriptor,
                info.sh_offset as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            println!("Unable to map address {:#X}", info.sh_virtual_address);
            unsafe {
                let error_location = libc::__errno_location();
                perror(error_location as *const libc::c_char);
            };
        }
        virtual_address.push(ptr);
    }
    let stack = ProgramStack::allocate(4096).unwrap();
    let pid = unsafe {
        syscall::clone(
            (header.e_entry + offset) as *const libc::c_void,
            stack.last_address,
            libc::CLONE_FILES | libc::CLONE_VM,
            0 as *const libc::c_void,
            0 as *const libc::pid_t,
            0 as *const libc::c_void,
            0 as *const libc::c_void
        )
    };
    println!("New process PID: {}", pid);
    unsafe {
        syscall::wait(0 as *const i32);
    }
}
