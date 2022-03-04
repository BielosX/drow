use libc::perror;

use crate::{syscall, Elf64Metadata, Elf64ProgramHeader, Elf64SectionHeader};

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
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                0,
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
            .filter(|h| h.p_virtual_address != 0);
        let offset = 0x20000;
        for info in program_info {
            let virtual_ptr = (info.p_virtual_address + offset) as *const libc::c_void;
            let ptr: *const libc::c_void = unsafe {
                syscall::mmap(
                    virtual_ptr,
                    info.p_memory_size as libc::size_t,
                    Elf64Loader::map_protection(info),
                    libc::MAP_FIXED | libc::MAP_SHARED,
                    file_descriptor,
                    info.p_offset as libc::off_t,
                )
            };
            if ptr == libc::MAP_FAILED {
                println!("Unable to map address {:#X}", info.p_virtual_address);
                unsafe {
                    let error_location = libc::__errno_location();
                    perror(error_location as *const libc::c_char);
                };
            }
            virtual_address.push(ptr);
        }
        let stack = ProgramStack::allocate(4096).unwrap();
        let pid = unsafe {
            syscall::clone(
                (elf_metadata.elf_header.e_entry + offset) as *const libc::c_void,
                stack.last_address,
                libc::CLONE_FILES | libc::CLONE_VM,
                0 as *const libc::c_void,
                0 as *const libc::pid_t,
                0 as *const libc::c_void,
                0 as *const libc::c_void,
            )
        };
        println!("New process PID: {}", pid);
        unsafe {
            syscall::wait(0 as *const i32);
        }
        Elf64Loader {
            stack,
            sections_virtual_addresses: virtual_address,
        }
    }
}
