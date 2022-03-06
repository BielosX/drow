use crate::cache::LibraryCache;
use crate::dynamic::Elf64Dynamic;
use crate::elf::*;
use crate::ld_path_loader::LdPathLoader;
use crate::loader::Elf64Loader;
use std::env;
use std::fs::File;
use std::io::BufReader;

mod cache;
mod dynamic;
mod elf;
mod ld_path_loader;
mod loader;
mod printer;
mod string_tables;
mod syscall;

const CACHE_PATH: &str = "/etc/ld.so.cache";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Path argument should be provided");
        std::process::exit(-1);
    }
    let ld_library_path = env::var("LD_LIBRARY_PATH").ok();
    if let Some(path) = ld_library_path.as_ref() {
        println!("LD_LIBRARY_PATH: {}", path);
    } else {
        println!("WARNING: LD_LIBRARY_PATH not set.");
    }
    let file_path = &args[1];
    let elf_file = File::open(file_path).expect("Unable to open elf file");
    let mut reader = BufReader::new(elf_file);
    let elf_metadata: Elf64Metadata = Elf64Metadata::load(&mut reader).unwrap();
    printer::print(&elf_metadata, &mut reader);
    let dynamic = Elf64Dynamic::load(&elf_metadata, &mut reader).unwrap();
    let library_cache = LibraryCache::load(&CACHE_PATH.to_string()).unwrap();
    let mut ld_path_loader = ld_library_path.as_ref().map(|a| LdPathLoader::new(a));
    for library in dynamic.required_libraries {
        if let Some(absolute_path) = library_cache.find(&library) {
            println!("Required library: {} => {}", library, absolute_path);
        } else {
            if let Some(path_loader) = ld_path_loader.as_mut() {
                if let Some(absolute_path) = path_loader.get(&library) {
                    println!("Required library: {} => {}", library, absolute_path);
                }
            } else {
                println!("Required library: {}", library);
            }
        }
    }
    for symbol in elf_metadata.symbol_table.iter() {
        println!("{}", symbol);
    }
    println!("Dynamic symbol table:");
    for symbol in elf_metadata.dynamic_symbol_table.iter() {
        println!("{}", symbol);
    }
    println!("Relocations:");
    for relocation in elf_metadata.relocations.iter() {
        println!("{}", relocation);
    }
    Elf64Loader::load(file_path, &elf_metadata);
}
