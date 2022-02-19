use crate::cache::LibraryCache;
use crate::dynamic::Elf64Dynamic;
use crate::elf::*;
use crate::loader::Elf64Loader;
use std::env;
use std::fs::File;
use std::io::BufReader;

mod cache;
mod dynamic;
mod elf;
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
    if let Some(path) = ld_library_path {
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
    for library in dynamic.required_libraries {
        println!("Required library: {}", library);
    }
    //Elf64Loader::load(file_path, &elf_metadata);
    LibraryCache::load(&CACHE_PATH.to_string()).unwrap();
}
