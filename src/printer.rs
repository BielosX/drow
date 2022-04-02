use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crate::string_tables::{
    convert_string_tables_content, get_string_tables_content, string_length,
};
use crate::{Elf64Metadata, Elf64SectionHeader, ELF64_SECTION_HEADER_STRING_TABLE};

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
    let section_names = elf_metadata
        .section_headers
        .get(elf_metadata.elf_header.e_section_name_string_table_index as usize)
        .unwrap();
    let section_names_table = string_tables_content
        .get(&section_names.sh_virtual_address)
        .unwrap();
    for header in elf_metadata.section_headers.iter() {
        let idx = header.sh_name as usize;
        let length = string_length(&section_names_table[idx..]);
        let end_idx = idx + length;
        let name = std::str::from_utf8(&section_names_table[idx..end_idx]).unwrap();
        println!("Section name: {}, header: {}", name, header);
    }
}
