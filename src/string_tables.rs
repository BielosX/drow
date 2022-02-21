use crate::{Elf64SectionHeader, ELF64_SECTION_HEADER_STRING_TABLE};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

pub fn get_string_tables_content<T: Read + Seek>(
    section_headers: &Vec<Elf64SectionHeader>,
    reader: &mut T,
) -> HashMap<u64, Vec<u8>> {
    let mut result = HashMap::new();
    let string_table_headers = section_headers
        .iter()
        .filter(|t| t.sh_type == ELF64_SECTION_HEADER_STRING_TABLE);
    for entry in string_table_headers {
        let content = get_string_table_content(entry, reader);
        result.insert(entry.sh_offset, content);
    }
    result
}

pub fn get_string_table_content<T: Read + Seek>(
    section_header: &Elf64SectionHeader,
    reader: &mut T,
) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(section_header.sh_size as usize, 0);
    reader
        .seek(SeekFrom::Start(section_header.sh_offset))
        .expect("Unable to change position");
    reader
        .read_exact(&mut buffer)
        .expect("Unable to read string table content");
    buffer
}

pub fn convert_string_tables_content(
    string_tables: &HashMap<u64, Vec<u8>>,
) -> HashMap<u64, Vec<&str>> {
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

pub fn string_length(string: &[u8]) -> usize {
    let mut index = 0;
    while string[index] != 0 {
        index += 1;
    }
    return index + 1;
}
