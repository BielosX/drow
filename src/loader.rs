use std::collections::{HashSet, VecDeque};
use std::ffi::CString;
use std::fs::File;
use std::io::BufReader;
use libc::perror;

use crate::{
    syscall, Elf64Dynamic, Elf64Metadata, Elf64ProgramHeader, Elf64SectionHeader, LdPathLoader,
    LibraryCache, ELF64_SECTION_HEADER_NO_BITS, PROGRAM_HEADER_TYPE_LOADABLE,
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
            let absolute_paths = self
                .resolve_path(library);
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
                result = Option::Some(BssMemory { address: ptr });
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

struct MappedMemory {
    pointer: *const libc::c_void,
    length: libc::size_t
}

impl MappedMemory {
    pub fn memory_map(file_descriptor: i32,
                      size: libc::size_t,
                      base_address: *const libc::c_void,
                      file_offset: libc::off_t,
                      protection: libc::c_int) -> Result<MappedMemory, String> {
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
            Result::Err(format!("Unable to map address {:#X}", base_address as u64))
        } else {
            Result::Ok(MappedMemory {
                pointer: ptr,
                length: size
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

pub struct Elf64Loader {
    mapped_memory: Vec<MappedMemory>,
    stack: ProgramStack,
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

    pub fn load(elf_metadata: &Elf64Metadata) -> Elf64Loader {
        let file_path_c_string = CString::new(elf_metadata.file_path.clone()).unwrap();
        let file_descriptor = unsafe {
            syscall::open(
                file_path_c_string.as_ptr(),
                libc::O_RDONLY,
            )
        };
        if file_descriptor < 0 {
            eprintln!("Unable to open file {}", elf_metadata.file_path);
            std::process::exit(-1);
        } else {
            println!("File descriptor: {}", file_descriptor);
        }
        let mut mapped_memory: Vec<MappedMemory> = Vec::new();
        let program_info = elf_metadata
            .program_headers
            .iter()
            .filter(|h| h.p_virtual_address != 0)
            .filter(|h| h.p_file_size > 0)
            .filter(|h| h.p_type == PROGRAM_HEADER_TYPE_LOADABLE);
        let offset = 0x20000;
        for info in program_info {
            let aligned_address = align_address(info.p_virtual_address + offset, info.p_align);
            let virtual_ptr = aligned_address as *const libc::c_void;
            println!(
                "Virtual Address {:X} will be loaded at {:X}",
                info.p_virtual_address, aligned_address
            );
            let protection = Elf64Loader::map_protection(info);
            let memory_mapped = MappedMemory::memory_map(file_descriptor,
                                                         info.p_memory_size as libc::size_t,
                                                         virtual_ptr,
                                                         info.p_offset as libc::off_t,
                                                         protection).unwrap();
            mapped_memory.push(memory_mapped);
        }
        let bss_section = elf_metadata
            .section_headers
            .iter()
            .filter(|h| h.sh_type == ELF64_SECTION_HEADER_NO_BITS);
        for bss in bss_section {
            BssMemory::allocate(bss, offset);
        }
        let stack = ProgramStack::allocate(4096).unwrap();
        let pid = unsafe {
            syscall::clone(
                (elf_metadata.elf_header.e_entry + offset) as *const libc::c_void,
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
        Elf64Loader {
            stack,
            mapped_memory
        }
    }
}
