use crate::cache::LibraryCache;
use crate::dynamic::Elf64Dynamic;
use crate::elf::*;
use crate::ld_path_loader::LdPathLoader;
use crate::loader::{DependenciesResolver, Elf64Loader};
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
    let elf_metadata: Elf64Metadata = Elf64Metadata::load(file_path, &mut reader).unwrap();
    let cache = LibraryCache::load(CACHE_PATH).expect("Unable to load cache");
    let mut ld_path_loader = ld_library_path.as_ref().map(|a| LdPathLoader::new(a));
    printer::print(&elf_metadata, &mut reader);
    /*
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
     */
    Elf64Loader::load(&elf_metadata);
    /*
    let mut dependencies_resolver = DependenciesResolver::new(cache, ld_path_loader);
    let queue = dependencies_resolver.resolve_in_loading_order(&elf_metadata);
    println!("Loading order: ");
    for entry in queue.iter() {
        println!("{}", entry.file_path);
    }
     */
}
