use libc::perror;

use crate::{syscall, Elf64Metadata, Elf64ProgramHeader, Elf64SectionHeader, PROGRAM_HEADER_TYPE_LOADABLE, ELF64_SECTION_HEADER_NO_BITS};

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

struct BssMemory {
    address: *const libc::c_void
}

impl BssMemory {
    fn allocate(section_header: &Elf64SectionHeader, offset: u64) -> Option<BssMemory> {
        let mut result = Option::None;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let bss_address = align_address(section_header.sh_virtual_address + offset, page_size as u64);
        let size = (section_header.sh_virtual_address + offset - bss_address) + section_header.sh_size;
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
                    address: ptr
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

pub struct Elf64Loader {
    sections_virtual_addresses: Vec<*const libc::c_void>,
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

    pub fn load(file_path: &String, elf_metadata: &Elf64Metadata) -> Elf64Loader {
        let file_descriptor =
            unsafe { syscall::open(file_path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if file_descriptor < 0 {
            eprintln!("Unable to open file");
            std::process::exit(-1);
        } else {
            println!("File descriptor: {}", file_descriptor);
        }
        let mut virtual_address: Vec<*const libc::c_void> = Vec::new();
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
            println!("Virtual Address {:X} will be loaded at {:X}", info.p_virtual_address, aligned_address);
            let protection = Elf64Loader::map_protection(info);
            let ptr: *const libc::c_void = unsafe {
                syscall::mmap(
                    virtual_ptr,
                    info.p_memory_size as libc::size_t,
                    protection,
                    libc::MAP_FIXED | libc::MAP_PRIVATE,
                    file_descriptor,
                    info.p_offset as libc::off_t,
                )
            };
            if ptr == libc::MAP_FAILED {
                println!("Unable to map address {:#X}", virtual_ptr as u64);
                unsafe {
                    let error_location = libc::__errno_location();
                    perror(error_location as *const libc::c_char);
                };
            }
            virtual_address.push(ptr);
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
                libc::CLONE_VM,
                0 as *const libc::c_void,
                0 as *const libc::pid_t,
                0 as *const libc::c_void,
                0 as *const libc::c_void,
            )
        };
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        if libc::WIFEXITED(status) {
            println!("Process exited normally with status: {}", libc::WEXITSTATUS(status));
        } else {
            println!("Process did not exit normally");
            if libc::WIFSIGNALED(status) {
                println!("Process terminated by a signal");
            }
        }
        Elf64Loader {
            stack,
            sections_virtual_addresses: virtual_address,
        }
    }
}
