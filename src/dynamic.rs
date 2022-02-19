use crate::string_tables::{get_string_tables_content, string_length};
use crate::{Elf64Metadata, Elf64SectionHeader, ELF64_SECTION_HEADER_DYNAMIC};
use std::io::{Read, Seek, SeekFrom};
use std::mem;

#[repr(C)]
#[derive(Copy, Clone)]
struct Elf64DynamicSection {
    tag: i64,
    value_or_pointer: u64,
}

struct Elf64DynamicData {
    required_libraries_string_table_offset: Vec<u64>,
    dynamic_string_table_address: u64,
}

impl Elf64DynamicData {
    fn new() -> Elf64DynamicData {
        Elf64DynamicData {
            required_libraries_string_table_offset: Vec::new(),
            dynamic_string_table_address: 0,
        }
    }
}

const DYNAMIC_TABLE_NEEDED: i64 = 1;
const DYNAMIC_TABLE_STRING_TABLE: i64 = 5;

pub struct Elf64Dynamic {
    pub required_libraries: Vec<String>,
}

impl Elf64Dynamic {
    fn load_dynamic_section<T: Read + Seek>(
        entry: &Elf64SectionHeader,
        metadata: &Elf64Metadata,
        elf64_dynamic: &mut Elf64Dynamic,
        reader: &mut T,
    ) {
        let mut elf_dynamic_data = Elf64DynamicData::new();
        let mut buffer: Vec<u8> = Vec::new();
        buffer.resize(entry.sh_size as usize, 0);
        reader.seek(SeekFrom::Start(entry.sh_offset));
        reader.read_exact(&mut buffer).expect("Error");
        let size = mem::size_of::<Elf64DynamicSection>();
        let len = buffer.len() / size;
        let mut dynamic_array: Vec<Elf64DynamicSection> = Vec::new();
        for x in 0..len {
            let from = x * size;
            let to = (x + 1) * size;
            let elem: Elf64DynamicSection =
                unsafe { std::ptr::read((&buffer[from..to]).as_ptr() as *const _) };
            dynamic_array.push(elem.clone());
        }
        for entry in dynamic_array.iter() {
            if entry.tag == DYNAMIC_TABLE_NEEDED {
                elf_dynamic_data
                    .required_libraries_string_table_offset
                    .push(entry.value_or_pointer);
                println!(
                    "Required libraries string table offset: {}",
                    entry.value_or_pointer
                );
            }
            if entry.tag == DYNAMIC_TABLE_STRING_TABLE {
                elf_dynamic_data.dynamic_string_table_address = entry.value_or_pointer;
                println!("Dynamic string table address: {}", entry.value_or_pointer);
            }
        }
        let string_tables = get_string_tables_content(&metadata.section_headers, reader);
        let string_table = string_tables
            .get(&elf_dynamic_data.dynamic_string_table_address)
            .unwrap();
        for entry in elf_dynamic_data.required_libraries_string_table_offset {
            let from = entry as usize;
            let len = string_length(&string_table[from..]);
            let to = from + len - 1;
            elf64_dynamic.required_libraries.push(
                std::str::from_utf8(&string_table[from..to])
                    .unwrap()
                    .to_string(),
            );
        }
    }

    pub fn load<T: Read + Seek>(
        metadata: &Elf64Metadata,
        reader: &mut T,
    ) -> Result<Elf64Dynamic, String> {
        let mut result = Elf64Dynamic {
            required_libraries: Vec::new(),
        };
        let dynamic_sections = metadata
            .section_headers
            .iter()
            .filter(|sec| sec.sh_type == ELF64_SECTION_HEADER_DYNAMIC);
        for entry in dynamic_sections {
            Elf64Dynamic::load_dynamic_section(entry, metadata, &mut result, reader);
        }
        Result::Ok(result)
    }
}
