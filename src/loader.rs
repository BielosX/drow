use libc::perror;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::BufReader;

use crate::{
    syscall, Elf64Dynamic, Elf64Metadata, Elf64ProgramHeader, Elf64ResolvedRelocationAddend,
    Elf64ResolvedSymbolTableEntry, Elf64SectionHeader, LdPathLoader, LibraryCache,
    ELF64_SECTION_HEADER_NO_BITS, PROGRAM_HEADER_TYPE_LOADABLE, RELOCATION_X86_64_GLOB_DAT,
    RELOCATION_X86_64_IRELATIV, RELOCATION_X86_64_JUMP_SLOT, RELOCATION_X86_64_RELATIVE,
};

fn align_address(address: u64, alignment: u64) -> u64 {
    let modulo = address % alignment;
    if modulo > 0 {
        address - modulo
    } else {
        address
    }
}

struct ProgramStack {
    address: *const libc::c_void,
    size: libc::size_t,
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
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr != libc::MAP_FAILED {
                println!("Allocated pointer: {:#X}", ptr as usize);
                result = Option::Some(ProgramStack {
                    address: ptr,
                    size,
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

impl Drop for ProgramStack {
    fn drop(&mut self) {
        if !self.address.is_null() {
            unsafe {
                syscall::munmap(self.address, self.size);
            }
        }
    }
}

pub struct DependenciesResolver {
    library_cache: LibraryCache,
    ld_path_loader: Option<LdPathLoader>,
}

impl DependenciesResolver {
    pub fn new(
        library_cache: LibraryCache,
        ld_path_loader: Option<LdPathLoader>,
    ) -> DependenciesResolver {
        DependenciesResolver {
            library_cache,
            ld_path_loader,
        }
    }

    fn resolve_path(&mut self, library: &String) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(absolute_paths) = self.library_cache.find(library) {
            result = absolute_paths.clone();
        } else {
            let path = self
                .ld_path_loader
                .as_mut()
                .map(|loader| loader.get(library))
                .flatten();
            if let Some(p) = path {
                result.push(p);
            }
        }
        result
    }

    pub fn resolve_direct_dependencies(
        &mut self,
        elf_metadata: &Elf64Metadata,
    ) -> Vec<Elf64Metadata> {
        let mut result = Vec::new();
        for library in elf_metadata.dynamic.required_libraries.iter() {
            println!("Required library: {}", library);
            let absolute_paths = self.resolve_path(library);
            for path in absolute_paths.iter() {
                let elf_file = File::open(path.clone()).expect("Unable to open elf file");
                let mut reader = BufReader::new(elf_file);
                let metadata = Elf64Metadata::load(path, &mut reader);
                if let Ok(loaded) = metadata {
                    result.push(loaded);
                }
            }
        }
        result
    }

    fn add_front<T: Clone>(queue: &mut VecDeque<T>, vector: &Vec<T>) {
        for entry in vector.iter() {
            queue.push_front(entry.clone());
        }
    }

    pub fn resolve_in_loading_order(&mut self, elf_metadata: &Elf64Metadata) -> Vec<Elf64Metadata> {
        let mut libraries: VecDeque<Elf64Metadata> = VecDeque::new();
        libraries.push_back(elf_metadata.clone());
        let mut queue = VecDeque::new();
        let dependencies = self.resolve_direct_dependencies(elf_metadata);
        DependenciesResolver::add_front(&mut queue, &dependencies);
        while let Some(entry) = queue.pop_front() {
            libraries.push_front(entry.clone());
            let entry_dependencies = self.resolve_direct_dependencies(&entry);
            DependenciesResolver::add_front(&mut queue, &entry_dependencies);
        }
        let mut result = Vec::new();
        let mut loaded: HashSet<String> = HashSet::new();
        for elem in libraries.iter() {
            if !loaded.contains(&elem.file_path) {
                loaded.insert(elem.file_path.clone());
                result.push(elem.clone());
            }
        }
        result
    }
}

struct BssMemory {
    address: *const libc::c_void,
    size: libc::size_t,
}

impl BssMemory {
    fn allocate(section_header: &Elf64SectionHeader, offset: u64) -> Option<BssMemory> {
        let mut result = Option::None;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let bss_address =
            align_address(section_header.sh_virtual_address + offset, page_size as u64);
        let size =
            (section_header.sh_virtual_address + offset - bss_address) + section_header.sh_size;
        unsafe {
            let ptr: *const libc::c_void = syscall::mmap(
                bss_address as *const libc::c_void,
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr != libc::MAP_FAILED {
                println!("BSS allocated at: {:#X}", ptr as usize);
                result = Option::Some(BssMemory {
                    address: ptr,
                    size: size as libc::size_t,
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

impl Drop for BssMemory {
    fn drop(&mut self) {
        if !self.address.is_null() {
            unsafe {
                syscall::munmap(self.address, self.size);
            }
        }
    }
}

struct MappedMemory {
    pointer: *const libc::c_void,
    length: libc::size_t,
}

impl MappedMemory {
    pub fn memory_map(
        file_descriptor: i32,
        size: libc::size_t,
        base_address: *const libc::c_void,
        file_offset: libc::off_t,
        protection: libc::c_int,
    ) -> Result<MappedMemory, String> {
        let ptr: *const libc::c_void = unsafe {
            syscall::mmap(
                base_address,
                size,
                protection,
                libc::MAP_FIXED | libc::MAP_PRIVATE,
                file_descriptor,
                file_offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            println!(
                "fd: {}, size: {}, addr: {:#X}, offset: {:#X}, prot: {}",
                file_descriptor, size, base_address as u64, file_offset, protection
            );
            Result::Err(format!("Unable to map address {:#X}", base_address as u64))
        } else {
            Result::Ok(MappedMemory {
                pointer: ptr,
                length: size,
            })
        }
    }
}

impl Drop for MappedMemory {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe {
                syscall::munmap(self.pointer, self.length);
            }
        }
    }
}

const DYNAMIC_LOADER_SO: &str = "ld-linux-x86-64.so.2";

pub struct Elf64Loader {
    mapped_memory: Vec<MappedMemory>,
    bss: Vec<BssMemory>,
    entry: u64,
    base_address: u64,
    global_symbols: HashMap<String, Elf64ResolvedSymbolTableEntry>,
    default_global_symbols: HashMap<String, Elf64ResolvedSymbolTableEntry>,
    dependency_resolver: DependenciesResolver,
}

impl Elf64Loader {
    fn map_protection(header: &Elf64ProgramHeader) -> libc::c_int {
        let mut flags: libc::c_int = 0;
        if header.execute() {
            flags = flags | libc::PROT_EXEC;
        }
        if header.write() {
            flags = flags | libc::PROT_WRITE;
        }
        if header.read() {
            flags = flags | libc::PROT_READ;
        }
        flags
    }

    pub fn new(dependency_resolver: DependenciesResolver) -> Elf64Loader {
        Elf64Loader {
            mapped_memory: Vec::new(),
            bss: Vec::new(),
            base_address: 0x20000,
            entry: 0,
            global_symbols: HashMap::new(),
            default_global_symbols: HashMap::new(),
            dependency_resolver,
        }
    }

    fn round_page_size(value: u64) -> u64 {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        if value % page_size == 0 {
            value
        } else {
            let x = value / page_size;
            page_size * (x + 1)
        }
    }

    fn update_global_symbols(&mut self, elf_metadata: &Elf64Metadata, offset: u64) {
        for symbol in elf_metadata.dynamic_symbol_table.iter() {
            if symbol.global() || symbol.weak() {
                let mut entry = symbol.clone();
                entry.value = entry.value + offset;
                if !self.global_symbols.contains_key(&entry.symbol_name) {
                    self.global_symbols
                        .insert(entry.symbol_name.clone(), entry.clone());
                }
                if symbol.symbol_name.contains("@@") {
                    let v: Vec<&str> = symbol.symbol_name.split("@@").collect();
                    let name = v[0].to_string();
                    if !self.default_global_symbols.contains_key(&name) {
                        self.default_global_symbols.insert(name, entry.clone());
                    }
                }
            }
        }
    }

    fn relocation_symbol_value(rela: &Elf64ResolvedRelocationAddend, offset: u64, value: u64) {
        unsafe {
            let destination_pointer = (rela.offset + offset) as *mut u64;
            println!(
                "Symbol found: {}. Address value at {:#X} will be changed to {:#X}",
                rela.symbol_name.clone(),
                destination_pointer as u64,
                value
            );
            *destination_pointer = value;
        }
    }

    fn relocate(&self, elf_metadata: &Elf64Metadata, offset: u64) {
        for rela in elf_metadata.relocations.iter() {
            if rela.relocation_type == RELOCATION_X86_64_JUMP_SLOT
                || rela.relocation_type == RELOCATION_X86_64_GLOB_DAT
            {
                if let Some(symbol) = self.global_symbols.get(&rela.symbol_name) {
                    Elf64Loader::relocation_symbol_value(rela, offset, symbol.value);
                } else {
                    let v: Vec<&str> = rela.symbol_name.split("@").collect();
                    let name = v[0].to_string();
                    if let Some(symbol) = self.default_global_symbols.get(&name) {
                        Elf64Loader::relocation_symbol_value(rela, offset, symbol.value);
                    } else {
                        println!("WARN: symbol {} not found", rela.symbol_name);
                    }
                }
            }
            if rela.relocation_type == RELOCATION_X86_64_RELATIVE {
                unsafe {
                    let destination_pointer = (rela.offset + offset) as *mut u64;
                    *destination_pointer = offset + rela.symbol_index;
                }
            }
            if rela.relocation_type == RELOCATION_X86_64_IRELATIV {
                unsafe {
                    let destination_pointer = (rela.offset + offset) as *mut u64;
                    *destination_pointer = offset + rela.symbol_index;
                }
            }
        }
    }

    pub fn load_program_header(&mut self, elf_metadata: &Elf64Metadata) {
        println!("Loading executable {}", elf_metadata.file_path);
        let file_descriptor = syscall::open_file(&elf_metadata.file_path).unwrap();
        let program_info = elf_metadata
            .program_headers
            .iter()
            .filter(|h| h.p_virtual_address != 0)
            .filter(|h| h.p_file_size > 0)
            .filter(|h| h.p_type == PROGRAM_HEADER_TYPE_LOADABLE);
        let offset = self.base_address;
        let mut last_address: u64 = 0;
        self.update_global_symbols(elf_metadata, offset);
        for info in program_info {
            let aligned_address = align_address(info.p_virtual_address + offset, info.p_align);
            let diff = info.p_virtual_address + offset - aligned_address;
            if aligned_address + info.p_memory_size > last_address {
                last_address = aligned_address + info.p_memory_size;
            }
            let virtual_ptr = aligned_address as *const libc::c_void;
            let memory_size =
                Elf64Loader::round_page_size(info.p_memory_size + diff) as libc::size_t;
            println!(
                "Virtual Address {:X} will be loaded at {:X}, size: {}",
                info.p_virtual_address, aligned_address, memory_size
            );
            let protection = Elf64Loader::map_protection(info);
            let memory_mapped = MappedMemory::memory_map(
                file_descriptor,
                memory_size,
                virtual_ptr,
                (info.p_offset - diff) as libc::off_t,
                protection,
            )
            .unwrap();
            self.mapped_memory.push(memory_mapped);
        }
        self.relocate(elf_metadata, offset);
        self.entry = elf_metadata.elf_header.e_entry + offset;
        self.base_address = Elf64Loader::round_page_size(last_address + 1);
        unsafe {
            syscall::close(file_descriptor);
        }
    }

    pub fn load(&mut self, elf_metadata: &Elf64Metadata) {
        let files = self
            .dependency_resolver
            .resolve_in_loading_order(elf_metadata);
        for file in files.iter() {
            if !file.file_path.contains(DYNAMIC_LOADER_SO) {
                if !file.program_headers.is_empty() {
                    self.load_program_header(file);
                }
            }
        }
    }

    pub fn execute(&self) {
        let stack = ProgramStack::allocate(4096).unwrap();
        let pid = unsafe {
            syscall::clone(
                self.entry as *const libc::c_void,
                stack.last_address,
                libc::CLONE_VM | libc::SIGCHLD,
                0 as *const libc::c_void,
                0 as *const libc::pid_t,
                0 as *const libc::c_void,
                0 as *const libc::c_void,
            )
        };
        println!("Process with PID {} started", pid);
        let mut status: libc::c_int = 0;
        let finished_pid = unsafe { libc::waitpid(pid, &mut status, 0) };
        if finished_pid == -1 {
            println!("waitpid failed");
            unsafe {
                let error_location = libc::__errno_location();
                perror(error_location as *const libc::c_char);
            }
        }
        println!("Process with PID {} finished", finished_pid);
        if libc::WIFEXITED(status) {
            println!(
                "Process exited normally with status: {}",
                libc::WEXITSTATUS(status)
            );
        } else {
            println!("Process did not exit normally");
            if libc::WIFSIGNALED(status) {
                println!("Process terminated by a signal");
            }
        }
    }
}
