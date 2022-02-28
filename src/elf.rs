use crate::string_tables::{get_string_table_content, string_length};
use libc::wchar_t;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::{iter, mem};

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

pub const PROGRAM_FLAG_EXECUTE: u32 = 1;
pub const PROGRAM_FLAG_WRITE: u32 = 2;
pub const PROGRAM_FLAG_READ: u32 = 4;

#[repr(C)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_virtual_address: u64,
    pub p_physical_address: u64,
    pub p_file_size: u64,
    pub p_memory_size: u64,
    pub p_align: u64,
}

pub const ELF64_SECTION_HEADER_UNUSED: u32 = 0;
pub const ELF64_SECTION_HEADER_SYMBOL_TABLE: u32 = 2;
pub const ELF64_SECTION_HEADER_STRING_TABLE: u32 = 3;
pub const ELF64_SECTION_HEADER_RELOCATION_ADDEND: u32 = 4;
pub const ELF64_SECTION_HEADER_DYNAMIC: u32 = 6;
pub const ELF64_SECTION_HEADER_DYNAMIC_SYMBOL_TABLE: u32 = 11;

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

pub const SECTION_FLAG_WRITE: u64 = 1;
pub const SECTION_FLAG_ALLOCATED: u64 = 2;
pub const SECTION_FLAG_EXECUTABLE_INSTRUCTIONS: u64 = 4;

#[repr(C)]
pub struct Elf64SymbolTableEntry {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_section_index: u16,
    pub st_value: u64,
    pub st_size: u64,
}

const SYMBOL_TYPE_BINDING_LOCAL: u8 = 0;
const SYMBOL_TYPE_BINDING_GLOBAL: u8 = 1;
const SYMBOL_TYPE_BINDING_WEAK: u8 = 2;
const SYMBOL_TYPE_BINDING_LOOS: u8 = 10;
const SYMBOL_TYPE_BINDING_HIOS: u8 = 12;
const SYMBOL_TYPE_BINDING_LOPROC: u8 = 13;
const SYMBOL_TYPE_BINDING_HIPROC: u8 = 15;

const SHN_UNDEF: u16 = 0;
const SHN_ABSOLUTE: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

impl Elf64SymbolTableEntry {
    pub fn binding(&self) -> u8 {
        self.st_info >> 4
    }

    pub fn symbol_type(&self) -> u8 {
        self.st_info & 0x0F
    }
}

pub struct Elf64ResolvedSymbolTableEntry {
    pub symbol_name: String,
    pub binding: u8,
    pub symbol_type: u8,
    pub section_index: u16,
    pub value: u64,
    pub size: u64,
}

#[repr(C)]
pub struct Elf64RelocationAddend {
    pub offset: u64,
    pub info: u64,
    pub addend: i32,
}

impl Elf64RelocationAddend {
    fn symbol_table_index(&self) -> u64 {
        self.info >> 32
    }

    fn relocation_type(&self) -> u64 {
        self.info & 0xFFFFFFFF
    }
}

const RELOCATION_X86_64_NONE: u64 = 0;
const RELOCATION_X86_64_64: u64 = 1;
const RELOCATION_X86_64_PC32: u64 = 2;
const RELOCATION_X86_64_GOT32: u64 = 3;
const RELOCATION_X86_64_PLT32: u64 = 4;
const RELOCATION_X86_64_COPY: u64 = 5;
const RELOCATION_X86_64_GLOB_DAT: u64 = 6;
const RELOCATION_X86_64_JUMP_SLOT: u64 = 7;
const RELOCATION_X86_64_RELATIVE: u64 = 8;
const RELOCATION_X86_64_GOTPCREL: u64 = 9;
const RELOCATION_X86_64_32: u64 = 10;
const RELOCATION_X86_64_32S: u64 = 11;
const RELOCATION_X86_64_16: u64 = 12;
const RELOCATION_X86_64_PC16: u64 = 13;
const RELOCATION_X86_64_8: u64 = 14;
const RELOCATION_X86_64_PC8: u64 = 15;
const RELOCATION_X86_64_DPTMOD64: u64 = 16;
const RELOCATION_X86_64_DTPOFF64: u64 = 17;
const RELOCATION_X86_64_TLSGD: u64 = 19;
const RELOCATION_X86_64_TLSLD: u64 = 20;
const RELOCATION_X86_64_DTPOFF32: u64 = 21;
const RELOCATION_X86_64_GOTTPOFF: u64 = 22;
const RELOCATION_X86_64_TPOFF32: u64 = 23;
const RELOCATION_X86_64_PC64: u64 = 24;
const RELOCATION_X86_64_GOTOFF64: u64 = 25;
const RELOCATION_X86_64_GOTOPC32: u64 = 26;

pub struct Elf64ResolvedRelocationAddend {
    pub symbol_name: String,
    pub symbol_index: u64,
    pub relocation_type: u64,
    pub offset: u64,
    pub addend: i32,
}

impl Display for Elf64ResolvedRelocationAddend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let relocation_types = [
            "R_X86_64_NONE",
            "R_X86_64_64",
            "R_X86_64_PC3",
            "R_X86_64_GOT32",
            "R_X86_64_PLT32",
            "R_X86_64_COPY",
            "R_X86_64_GLOB_DAT",
            "R_X86_64_JUMP_SLOT",
            "R_X86_64_RELATIVE",
            "R_X86_64_GOTPCREL",
            "R_X86_64_32",
            "R_X86_64_32S",
            "R_X86_64_16",
            "R_X86_64_PC16",
            "R_X86_64_8",
            "R_X86_64_PC8",
            "R_X86_64_DPTMOD64",
            "R_X86_64_DTPOFF64",
            "R_X86_64_TLSGD",
            "R_X86_64_TLSLD",
            "R_X86_64_DTPOFF32",
            "R_X86_64_GOTTPOFF",
            "R_X86_64_TPOFF32",
            "R_X86_64_PC64",
            "R_X86_64_GOTOFF64",
            "R_X86_64_GOTOPC32",
        ];
        let values: Vec<u64> = (0..26).collect();
        let relocation_map: HashMap<u64, &str> =
            Iterator::zip(values.iter().cloned(), relocation_types).collect();
        f.write_str(format!("| Symbol name: {}", self.symbol_name).as_str())?;
        f.write_str(
            format!(
                "| Relocation type: {}",
                relocation_map
                    .get(&self.relocation_type)
                    .unwrap_or(&"Other")
            )
            .as_str(),
        )?;
        f.write_str(format!("| Symbol table index: {}", self.symbol_index).as_str())?;
        f.write_str(format!("| Offset: {:X}", self.offset).as_str())?;
        f.write_str(format!("| Addend: {:X}", self.offset).as_str())?;
        f.write_str(format!("|").as_str())
    }
}

impl Display for Elf64ResolvedSymbolTableEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let symbol_types: HashMap<u8, &str> = [
            (0, "No type specified"),
            (1, "Data object"),
            (2, "Function entry point"),
            (3, "Section"),
            (4, "Source file"),
        ]
        .iter()
        .cloned()
        .collect();
        let symbol_bindings: HashMap<u8, &str> = [(0, "Local"), (1, "Global"), (2, "Weak")]
            .iter()
            .cloned()
            .collect();
        f.write_str(format!("| Symbol name: {}", self.symbol_name).as_str())?;
        f.write_str(
            format!(
                " | Symbol type: {}",
                symbol_types.get(&self.symbol_type).unwrap_or(&"Other")
            )
            .as_str(),
        )?;
        f.write_str(
            format!(
                " | Binding: {}",
                symbol_bindings.get(&self.binding).unwrap_or(&"Other")
            )
            .as_str(),
        );
        f.write_str(format!("| Value: {:X}", self.value).as_str())?;
        if self.section_index == SHN_UNDEF {
            f.write_str("| Section Index: UNDEFINED")?;
        }
        if self.section_index == SHN_ABSOLUTE {
            f.write_str("| Section Index: ABSOLUTE")?;
        }
        if self.section_index == SHN_COMMON {
            f.write_str("| Section Index: COMMON")?;
        }
        f.write_str(" |")
    }
}

fn make_flags_string(flags: &Vec<&str>) -> String {
    let mut flags_string = String::new();
    for x in 0..flags.len() {
        if x != (flags.len() - 1) {
            flags_string.push_str(format!("{} & ", flags[x]).as_str());
        } else {
            flags_string.push_str(flags[x]);
        }
    }
    flags_string
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
        if self.sh_type == ELF64_SECTION_HEADER_SYMBOL_TABLE {
            f.write_str(format!("|Section string table: {}", self.sh_link).as_str())?;
        }
        let mut flags: Vec<&str> = Vec::new();
        if self.sh_flags & SECTION_FLAG_WRITE > 0 {
            flags.push("WRITABLE_DATA");
        }
        if self.sh_flags & SECTION_FLAG_ALLOCATED > 0 {
            flags.push("ALLOCATED");
        }
        if self.sh_flags & SECTION_FLAG_EXECUTABLE_INSTRUCTIONS > 0 {
            flags.push("EXECUTABLE_INSTRUCTIONS");
        }
        f.write_str(format!("|Flags: {}", make_flags_string(&flags)).as_str())?;
        f.write_str(format!("|Flags value: {:X}", self.sh_flags).as_str())?;
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
        let mut flags: Vec<&str> = Vec::new();
        if self.p_flags & PROGRAM_FLAG_EXECUTE > 0 {
            flags.push("EXECUTE");
        }
        if self.p_flags & PROGRAM_FLAG_READ > 0 {
            flags.push("READ");
        }
        if self.p_flags & PROGRAM_FLAG_WRITE > 0 {
            flags.push("WRITE");
        }
        f.write_str(format!("|Flags: {}", make_flags_string(&flags)).as_str())?;
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
    pub symbol_table: Vec<Elf64ResolvedSymbolTableEntry>,
    pub dynamic_symbol_table: Vec<Elf64ResolvedSymbolTableEntry>,
    pub relocations: Vec<Elf64ResolvedRelocationAddend>,
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

    fn load_symbol_table<T: Read + Seek>(
        section_headers: &Vec<Elf64SectionHeader>,
        reader: &mut T,
        table_type: u32,
    ) -> Result<Vec<Elf64ResolvedSymbolTableEntry>, String> {
        let mut result: Vec<Elf64ResolvedSymbolTableEntry> = Vec::new();
        for table in section_headers
            .iter()
            .filter(|header| header.sh_type == table_type)
        {
            let section_string_table = get_string_table_content(
                &section_headers.get(table.sh_link as usize).unwrap(),
                reader,
            );
            reader.seek(SeekFrom::Start(table.sh_offset));
            let entries = table.sh_size / size_of::<Elf64SymbolTableEntry>() as u64;
            for _ in 0..entries {
                let mut buffer: Vec<u8> = Vec::new();
                buffer.resize(size_of::<Elf64SymbolTableEntry>(), 0);
                reader
                    .read_exact(&mut buffer)
                    .map_err(|err| format!("Unable to read file: {:?}", err))?;
                let section_entry: Elf64SymbolTableEntry =
                    unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };
                let len = string_length(&section_string_table[section_entry.st_name as usize..]);
                let from = section_entry.st_name as usize;
                let to = from + len;
                let symbol_name = std::str::from_utf8(&section_string_table[from..to])
                    .unwrap()
                    .to_string();
                let resolved_entry = Elf64ResolvedSymbolTableEntry {
                    symbol_name,
                    binding: section_entry.binding(),
                    symbol_type: section_entry.symbol_type(),
                    section_index: section_entry.st_section_index,
                    value: section_entry.st_value,
                    size: section_entry.st_size,
                };
                result.push(resolved_entry);
            }
        }
        Result::Ok(result)
    }

    fn load_relocation_entries<T: Read + Seek>(
        section_headers: &Vec<Elf64SectionHeader>,
        dynamic_symbol_table: &Vec<Elf64ResolvedSymbolTableEntry>,
        reader: &mut T,
    ) -> Vec<Elf64ResolvedRelocationAddend> {
        let mut result = Vec::new();
        for header in section_headers.iter() {
            if header.sh_type == ELF64_SECTION_HEADER_RELOCATION_ADDEND {
                reader.seek(SeekFrom::Start(header.sh_offset));
                let entries = header.sh_size / size_of::<Elf64SymbolTableEntry>() as u64;
                for _ in 0..entries {
                    let mut buffer: Vec<u8> = Vec::new();
                    buffer.resize(size_of::<Elf64SymbolTableEntry>(), 0);
                    reader
                        .read_exact(&mut buffer)
                        .map_err(|err| format!("Unable to read file: {:?}", err));
                    let relocation_entry: Elf64RelocationAddend =
                        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };
                    let symbol_name: String = dynamic_symbol_table
                        .get(relocation_entry.symbol_table_index() as usize)
                        .map(|s| s.symbol_name.clone())
                        .unwrap_or("".to_string());
                    let resolved_entry = Elf64ResolvedRelocationAddend {
                        symbol_name,
                        relocation_type: relocation_entry.relocation_type(),
                        offset: relocation_entry.offset,
                        addend: relocation_entry.addend,
                        symbol_index: relocation_entry.symbol_table_index()
                    };
                    result.push(resolved_entry);
                }
            }
        }
        result
    }

    pub fn load<T: Read + Seek>(reader: &mut T) -> Result<Elf64Metadata, String> {
        let elf_header = Elf64Metadata::load_elf_header(reader)?;
        Elf64Metadata::check_header(&elf_header)?;
        let program_headers = Elf64Metadata::load_program_headers(&elf_header, reader)?;
        let section_headers = Elf64Metadata::load_section_headers(&elf_header, reader)?;
        let symbol_table = Elf64Metadata::load_symbol_table(
            &section_headers,
            reader,
            ELF64_SECTION_HEADER_SYMBOL_TABLE,
        )?;
        let dynamic_symbol_table = Elf64Metadata::load_symbol_table(
            &section_headers,
            reader,
            ELF64_SECTION_HEADER_DYNAMIC_SYMBOL_TABLE,
        )?;
        let relocations =
            Elf64Metadata::load_relocation_entries(&section_headers, &dynamic_symbol_table, reader);
        let result = Elf64Metadata {
            elf_header,
            program_headers,
            section_headers,
            symbol_table,
            dynamic_symbol_table,
            relocations,
        };
        Result::Ok(result)
    }
}
