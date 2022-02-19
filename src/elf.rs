use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Read, Seek, SeekFrom};
use std::mem;

const IDENT_SIZE: usize = 16;

#[repr(C)]
pub struct Elf64Header {
    pub e_ident: [u8; IDENT_SIZE],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_program_header_offset: u64,
    pub e_section_header_offset: u64,
    pub e_flags: u32,
    pub e_elf_header_size: u16,
    pub e_program_header_entry_size: u16,
    pub e_program_header_entries: u16,
    pub e_section_header_entry_size: u16,
    pub e_section_header_entries: u16,
    pub e_section_name_string_table_index: u16,
}

#[repr(C)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_offset: u64,
    pub p_virtual_address: u64,
    pub p_physical_address: u64,
    pub p_file_size: u64,
    pub p_memory_size: u64,
    pub p_align: u64,
}

pub const ELF64_SECTION_HEADER_UNUSED: u32 = 0;
pub const ELF64_SECTION_HEADER_STRING_TABLE: u32 = 3;
pub const ELF64_SECTION_HEADER_DYNAMIC: u32 = 6;

#[repr(C)]
pub struct Elf64SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_virtual_address: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_address_align: u64,
    pub sh_entry_size: u64,
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

pub struct Elf64Metadata {
    pub elf_header: Elf64Header,
    pub program_headers: Vec<Elf64ProgramHeader>,
    pub section_headers: Vec<Elf64SectionHeader>,
}

impl Elf64Metadata {
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
        Elf64Metadata::check_file_ident(header)?;
        Elf64Metadata::check_class(header)?;
        Elf64Metadata::check_endian(header)?;
        Elf64Metadata::check_machine(header)
    }

    fn load_elf_header<T: Read>(reader: &mut T) -> Result<Elf64Header, String> {
        let mut header_buffer: Vec<u8> = Vec::new();
        header_buffer.resize(mem::size_of::<Elf64Header>(), 0);
        reader
            .read_exact(&mut header_buffer)
            .map_err(|err| format!("Unable to read file: {:?}", err))?;
        let header: Elf64Header =
            unsafe { std::ptr::read_unaligned(header_buffer.as_ptr() as *const _) };
        Result::Ok(header)
    }

    fn load_program_headers<T: Read + Seek>(
        header: &Elf64Header,
        reader: &mut T,
    ) -> Result<Vec<Elf64ProgramHeader>, String> {
        reader
            .seek(SeekFrom::Start(header.e_program_header_offset))
            .map_err(|err| format!("Unable to read file: {:?}", err))?;
        let mut program_headers: Vec<Elf64ProgramHeader> = Vec::new();
        for _ in 0..header.e_program_header_entries {
            let mut program_header_buffer: Vec<u8> = Vec::new();
            program_header_buffer.resize(mem::size_of::<Elf64ProgramHeader>(), 0);
            reader
                .read_exact(&mut program_header_buffer)
                .map_err(|err| format!("Unable to read file: {:?}", err))?;
            let program_header: Elf64ProgramHeader =
                unsafe { std::ptr::read_unaligned(program_header_buffer.as_ptr() as *const _) };
            program_headers.push(program_header);
        }
        Result::Ok(program_headers)
    }

    fn load_section_headers<T: Read + Seek>(
        header: &Elf64Header,
        reader: &mut T,
    ) -> Result<Vec<Elf64SectionHeader>, String> {
        reader
            .seek(SeekFrom::Start(header.e_section_header_offset))
            .map_err(|err| format!("Unable to read file: {:?}", err))?;
        let mut section_headers: Vec<Elf64SectionHeader> = Vec::new();
        for _ in 0..header.e_section_header_entries {
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(mem::size_of::<Elf64SectionHeader>(), 0);
            reader
                .read_exact(&mut buffer)
                .map_err(|err| format!("Unable to read file: {:?}", err))?;
            let section_header: Elf64SectionHeader =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };
            section_headers.push(section_header);
        }
        Result::Ok(section_headers)
    }

    pub fn load<T: Read + Seek>(reader: &mut T) -> Result<Elf64Metadata, String> {
        let elf_header = Elf64Metadata::load_elf_header(reader)?;
        Elf64Metadata::check_header(&elf_header)?;
        let program_headers = Elf64Metadata::load_program_headers(&elf_header, reader)?;
        let section_headers = Elf64Metadata::load_section_headers(&elf_header, reader)?;
        let result = Elf64Metadata {
            elf_header,
            program_headers,
            section_headers,
        };
        Result::Ok(result)
    }
}
