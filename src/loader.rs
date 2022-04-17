use libc::{perror, printf, wchar_t};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::BufReader;
use std::mem::size_of;
use std::{arch, mem, ptr};

use crate::{syscall, Elf64Dynamic, Elf64Metadata, Elf64ProgramHeader, Elf64ResolvedRelocationAddend, Elf64ResolvedSymbolTableEntry, Elf64SectionHeader, LdPathLoader, LibraryCache, ELF64_SECTION_HEADER_NO_BITS, PROGRAM_HEADER_TYPE_LOADABLE, RELOCATION_X86_64_64, RELOCATION_X86_64_COPY, RELOCATION_X86_64_GLOB_DAT, RELOCATION_X86_64_IRELATIV, RELOCATION_X86_64_JUMP_SLOT, RELOCATION_X86_64_RELATIVE, SYMBOL_BINDING_GLOBAL, SYMBOL_TYPE_OBJECT, SYMBOL_TYPE_FUNCTION};

fn align_address(address: u64, alignment: u64) -> u64 {
    let modulo = address % alignment;
    if modulo > 0 {
        address - modulo
    } else {
        address
    }
}

const DEFAULT_STACK_SIZE: libc::size_t = 1024 * 1000 * 10;

struct ProgramStack {
    address: *const libc::c_void,
    size: libc::size_t,
    last_address: *const libc::c_void,
}

extern "C" {
    static _rtld_global_ro: u8;
    static __tunable_get_val: u8;
}

impl ProgramStack {
    fn allocate_default_size() -> Option<ProgramStack> {
        ProgramStack::allocate(DEFAULT_STACK_SIZE)
    }

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

#[repr(C)]
struct HandlerArguments {
    entry: u64,
    init_functions: Vec<u64>,
    last_stack_address: u64,
}

unsafe fn run_init_functions(args: *const HandlerArguments) {
    for init in (*args).init_functions.iter() {
        let pointer = init.clone() as *const ();
        let function = mem::transmute::<*const (), unsafe extern "C" fn()>(pointer);
        function();
    }
    println!("INITIALIZED SUCCESSFULLY");
}

unsafe fn handle_same_process(args: *const HandlerArguments) {
    run_init_functions(args);
    arch::asm!(
        "mov rax, {entry}",
        "mov rbx, {stack}",
        "mov rsp, rbx",
        "jmp rax",
        entry = in(reg) (*args).entry,
        stack = in(reg) (*args).last_stack_address
    );
}

unsafe fn handle(args: *const HandlerArguments) {
    /*
    GLIBC has two important init functions:
        _init_first (0x02d1a0)
        check_stdfiles_vtables (0x02d210)
     */
    run_init_functions(args);
    let entry_pointer = (*args).entry as *const ();
    let function = mem::transmute::<*const (), fn()>(entry_pointer);
    function();
}

pub struct Elf64Loader {
    mapped_memory: Vec<MappedMemory>,
    entry: u64,
    base_address: u64,
    global_symbols: HashMap<String, Elf64ResolvedSymbolTableEntry>,
    default_global_symbols: HashMap<String, Elf64ResolvedSymbolTableEntry>,
    dependency_resolver: DependenciesResolver,
    init_functions: Vec<u64>,
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

    fn init_linker_symbols() -> HashMap<String, Elf64ResolvedSymbolTableEntry> {
        let mut result = HashMap::new();
        let value = unsafe {
            let pointer: *const u8 = ptr::addr_of!(_rtld_global_ro) as *const u8;
            println!("Value at 0xb8: {:#X}", *(pointer.offset(0xb8)));
            pointer as u64
        };
        println!("_rtld_global_ro located at: {:#X}", value);
        let entry = Elf64ResolvedSymbolTableEntry {
            symbol_name: String::from("_rtld_global_ro"),
            binding: SYMBOL_BINDING_GLOBAL,
            symbol_type: SYMBOL_TYPE_OBJECT,
            section_index: 0,
            value,
            size: size_of::<u8>() as u64,
        };
        result.insert(String::from("_rtld_global_ro"), entry);
        let value = unsafe {
            let pointer: *const u8 = ptr::addr_of!(__tunable_get_val) as *const u8;
            pointer as u64
        };
        println!("__tunable_get_val located at: {:#X}", value);
        let entry = Elf64ResolvedSymbolTableEntry {
            symbol_name: String::from("__tunable_get_val"),
            binding: SYMBOL_BINDING_GLOBAL,
            symbol_type: SYMBOL_TYPE_FUNCTION,
            section_index: 0,
            value,
            size: size_of::<u8>() as u64,
        };
        result.insert(String::from("__tunable_get_val"), entry);
        result
    }

    pub fn new(dependency_resolver: DependenciesResolver) -> Elf64Loader {
        let linker_symbols = Elf64Loader::init_linker_symbols();
        Elf64Loader {
            mapped_memory: Vec::new(),
            base_address: 0x20000,
            entry: 0,
            global_symbols: linker_symbols.clone(),
            default_global_symbols: linker_symbols,
            dependency_resolver,
            init_functions: Vec::new(),
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
                if !symbol.undefined() {
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
            } else {
                println!(
                    "Symbol {} in {} is UNDEFINED",
                    symbol.symbol_name, elf_metadata.file_path
                );
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

    fn get_symbol(
        &self,
        rela: &Elf64ResolvedRelocationAddend,
    ) -> Option<Elf64ResolvedSymbolTableEntry> {
        if let Some(symbol) = self.global_symbols.get(&rela.symbol_name) {
            Option::Some(symbol.clone())
        } else {
            let v: Vec<&str> = rela.symbol_name.split("@").collect();
            let name = String::from(v[0].to_string().trim_matches('\0'));
            if let Some(symbol) = self.default_global_symbols.get(&name) {
                Option::Some(symbol.clone())
            } else {
                println!("WARN: symbol {} not found", rela.symbol_name);
                Option::None
            }
        }
    }

    fn relocate(&self, elf_metadata: &Elf64Metadata, offset: u64) {
        for rela in elf_metadata.relocations.iter() {
            if rela.relocation_type == RELOCATION_X86_64_JUMP_SLOT
                || rela.relocation_type == RELOCATION_X86_64_GLOB_DAT
            {
                if let Some(symbol) = self.get_symbol(rela) {
                    if symbol.undefined() {
                        println!("SYMBOL {} UNDEFINED!!", symbol.symbol_name);
                    }
                    let mut value = symbol.value;
                    if symbol.indirect_function() {
                        let pointer = symbol.value as *const ();
                        let resolve_function = unsafe {
                            mem::transmute::<*const (), unsafe extern "C" fn() -> u64>(pointer)
                        };
                        let function_pointer = unsafe { resolve_function() };
                        value = function_pointer;
                        println!(
                            "INDIRECT FUNCTION {} RESOLVED: {:#X}",
                            symbol.symbol_name,
                            value.clone()
                        );
                    }
                    Elf64Loader::relocation_symbol_value(rela, offset, value);
                }
            }
            if rela.relocation_type == RELOCATION_X86_64_64 {
                if let Some(symbol) = self.get_symbol(rela) {
                    if symbol.undefined() {
                        println!("SYMBOL {} UNDEFINED!!", symbol.symbol_name);
                    }
                    unsafe {
                        let destination_pointer = (rela.offset + offset) as *mut i64;
                        let value = (symbol.value as i64) + (rela.addend as i64);
                        println!(
                            "Symbol found: {}. Address value at {:#X} will be changed to {:#X} (SYMBOL + ADDEND)",
                            rela.symbol_name.clone(),
                            destination_pointer as u64,
                            value
                        );
                        *destination_pointer = value;
                    }
                }
            }
            if rela.relocation_type == RELOCATION_X86_64_RELATIVE
                || rela.relocation_type == RELOCATION_X86_64_IRELATIV
            {
                unsafe {
                    let destination_pointer = (rela.offset + offset) as *mut i64;
                    *destination_pointer = (offset as i64) + (rela.addend as i64);
                }
            }
            if rela.relocation_type == RELOCATION_X86_64_COPY {
                if let Some(symbol) = self.get_symbol(rela) {
                    let destination_addr = rela.offset + offset;
                    let destination_pointer = destination_addr.clone() as *mut libc::c_void;
                    println!(
                        "Symbol {} of size {} will be copied to {:#X} from {:#X}",
                        symbol.symbol_name, symbol.size, destination_addr, symbol.value
                    );
                    unsafe {
                        libc::memcpy(
                            destination_pointer,
                            symbol.value as *const libc::c_void,
                            symbol.size as libc::size_t,
                        );
                    }
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
            let file_offset = info.p_offset - diff;
            println!(
                "Virtual Address {:#X} will be loaded at {:#X}, size: {}, file offset: {:#X}, last addr: {:#X}",
                info.p_virtual_address, aligned_address, memory_size, file_offset, aligned_address + (memory_size as u64)
            );
            let protection = Elf64Loader::map_protection(info);
            let memory_mapped = MappedMemory::memory_map(
                file_descriptor,
                memory_size,
                virtual_ptr,
                file_offset as libc::off_t,
                protection,
            )
            .unwrap();
            self.mapped_memory.push(memory_mapped);
        }
        Elf64Loader::zero_bss_section(elf_metadata, offset);
        self.relocate(elf_metadata, offset);
        self.entry = elf_metadata.elf_header.e_entry + offset;
        self.base_address = Elf64Loader::round_page_size(last_address + 1);
        unsafe {
            syscall::close(file_descriptor);
        }
    }

    fn append_init_functions(init_array: &mut Vec<u64>, dynamic: &Elf64Dynamic, base: u64) {
        println!(
            "Init function: {:#X}, init_array: {:#X}, init_array_size: {}",
            dynamic.init_function, dynamic.init_array, dynamic.init_array_size
        );
        if dynamic.init_function > 0 {
            let value = dynamic.init_function + base;
            init_array.push(value);
            println!("Init function at: {:#X}, base: {:#X}", value, base);
        }
        if dynamic.init_array > 0 && dynamic.init_array_size > 0 {
            unsafe {
                let value = dynamic.init_array + base;
                println!("Init array at: {:#X}, base: {:#X}", value, base);
                let pointer = value as *const u64;
                for x in 0..(dynamic.init_array_size / (size_of::<u64>() as u64)) {
                    let elem_pointer = *(pointer.offset(x as isize));
                    init_array.push(elem_pointer);
                    println!(
                        "Init array element points to: {:#X}, already reallocated",
                        elem_pointer
                    );
                }
            }
        }
    }

    fn zero_bss_section(elf_metadata: &Elf64Metadata, base: u64) {
        let bss_sections = elf_metadata
            .section_headers
            .iter()
            .filter(|h| h.writable() && h.sh_type == ELF64_SECTION_HEADER_NO_BITS && h.sh_size > 0);
        for section in bss_sections {
            let address = section.sh_virtual_address + base;
            println!(
                "BSS section loaded at {:#X} with size {} will be cleared",
                address, section.sh_size
            );
            let size = section.sh_size;
            unsafe {
                libc::memset(address as *mut libc::c_void, 0, size as libc::size_t);
            }
        }
    }

    pub fn load(&mut self, elf_metadata: &Elf64Metadata) {
        let files = self
            .dependency_resolver
            .resolve_in_loading_order(elf_metadata);
        for file in files.iter() {
            if !file.file_path.contains(DYNAMIC_LOADER_SO) {
                if !file.program_headers.is_empty() {
                    let base = self.base_address;
                    self.load_program_header(file);
                    Elf64Loader::append_init_functions(
                        &mut self.init_functions,
                        &file.dynamic,
                        base,
                    );
                }
            }
        }
    }

    pub fn execute_same_process(&self) {
        let stack = ProgramStack::allocate_default_size().unwrap();
        println!("Starting in the same process");
        let args = HandlerArguments {
            entry: self.entry,
            init_functions: self.init_functions.clone(),
            last_stack_address: stack.last_address as u64,
        };
        unsafe {
            handle_same_process(&args as *const HandlerArguments);
        }
    }

    pub fn execute(&self) {
        let stack = ProgramStack::allocate_default_size().unwrap();
        let args = HandlerArguments {
            entry: self.entry,
            init_functions: self.init_functions.clone(),
            last_stack_address: stack.address as u64,
        };
        let pid = unsafe {
            syscall::clone(
                handle as *const libc::c_void,
                stack.last_address,
                libc::CLONE_VM | libc::SIGCHLD,
                ptr::addr_of!(args) as *const libc::c_void,
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
