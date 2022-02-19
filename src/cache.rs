use crate::syscall;
use libc::{size_t, stat};
use std::collections::HashMap;
use std::{mem, ptr};

pub struct LibraryCache {
    cache: HashMap<String, String>,
}

const CACHE_MAGIC_NEW: &str = "glibc-ld.so.cache";
const CACHE_VERSION: &str = "1.1";

impl LibraryCache {
    fn new() -> LibraryCache {
        LibraryCache {
            cache: HashMap::new(),
        }
    }

    fn get_file_size(descriptor: i32) -> i64 {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.resize(mem::size_of::<libc::stat>(), 0);
        unsafe {
            syscall::fstat(descriptor, buffer.as_ptr() as *const libc::stat);
        }
        let file_info: libc::stat = unsafe { ptr::read(buffer.as_ptr() as *const _) };
        file_info.st_size
    }

    unsafe fn compare_bytes(vector: &Vec<u8>, pointer: *const u8) -> bool {
        let mut result = true;
        for x in 0..vector.len() {
            if vector[x] != *pointer.offset(x as isize) {
                result = false;
                break;
            }
        }
        result
    }

    pub fn load(path: &String) -> Result<LibraryCache, String> {
        let mut cache = LibraryCache::new();
        let mut result = Ok(cache);
        let cache_magic_new: Vec<u8> = CACHE_MAGIC_NEW.chars().map(|ch| ch as u8).collect();
        let cache_version: Vec<u8> = CACHE_VERSION.chars().map(|ch| ch as u8).collect();
        let file_descriptor =
            unsafe { syscall::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if file_descriptor < 0 {
            result = Result::Err("Unable to open cache file".to_string());
        } else {
            let file_size = LibraryCache::get_file_size(file_descriptor);
            println!("Cache file size: {}", file_size);
            unsafe {
                let file_ptr: *const libc::c_void = syscall::mmap(
                    ptr::null(),
                    file_size as size_t,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file_descriptor,
                    0,
                );
                if file_ptr != libc::MAP_FAILED {
                    let mut elem_ptr: *const libc::c_void = file_ptr.clone();
                    if LibraryCache::compare_bytes(&cache_magic_new, elem_ptr as *const u8) {
                        println!("Proper cache magic detected: {}", CACHE_MAGIC_NEW);
                    } else {
                        println!("Wrong cache magic detected, should be: {}", CACHE_MAGIC_NEW);
                    }
                    elem_ptr = elem_ptr.offset(cache_magic_new.len() as isize);
                    if LibraryCache::compare_bytes(&cache_version, elem_ptr as *const u8) {
                        println!("Proper cache version detected: {}", CACHE_VERSION);
                    } else {
                        println!("Wrong cache version detected, should be: {}", CACHE_VERSION);
                    }
                    elem_ptr = elem_ptr.offset(cache_version.len() as isize);
                    syscall::munmap(file_ptr, file_size as size_t);
                } else {
                    result = Result::Err("Unable to mmap file".to_string());
                }
                syscall::close(file_descriptor);
            }
        }
        result
    }
}
