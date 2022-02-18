use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use crate::{ELF64_SECTION_HEADER_STRING_TABLE, Elf64Metadata, Elf64SectionHeader};

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

fn string_length(string: &[u8]) -> usize {
    let mut index = 0;
    while string[index] != 0 {
        index += 1;
    }
    return index + 1;
}

pub fn print<T: Read + Seek>(elf_metadata: &Elf64Metadata, reader: &mut T) {
    print!("{}\n", elf_metadata.elf_header);
    println!("Program headers");
    for header in elf_metadata.program_headers.iter() {
        println!("{}", header);
    }
    let string_tables_content = get_string_tables_content(&elf_metadata.section_headers, reader);
    let string_tables_content_converted = convert_string_tables_content(&string_tables_content);
    for (key, value) in string_tables_content_converted.iter() {
        println!("String table at {} content:", key);
        for entry in value.iter() {
            println!("{}", entry);
        }
    }
    println!("Section headers");
    let section_names = elf_metadata.section_headers
        .get(elf_metadata.elf_header.e_section_name_string_table_index as usize)
        .unwrap();
    let section_names_table = string_tables_content.get(&section_names.sh_offset).unwrap();
    for header in elf_metadata.section_headers.iter() {
        let idx = header.sh_name as usize;
        let length = string_length(&section_names_table[idx..]);
        let end_idx = idx + length;
        let name = std::str::from_utf8(&section_names_table[idx..end_idx]).unwrap();
        println!("Section name: {}, header: {}", name, header);
    }
}