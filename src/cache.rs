use crate::syscall;
use libc::{size_t, stat};
use std::collections::HashMap;
use std::{mem, ptr};
use std::mem::size_of;

pub struct LibraryCache {
    cache: HashMap<String, String>,
}

const CACHE_MAGIC_NEW: &str = "glibc-ld.so.cache";
const CACHE_VERSION: &str = "1.1";

#[repr(C)]
#[derive(Copy, Clone)]
struct CacheEntry {
    flags: i32,
    key: u32,
    value: u32,
    os_version: u32,
    hwcap: u64
}

impl LibraryCache {
    pub fn find(&self, key: &String) -> Option<&String> {
        self.cache.get(key)
    }

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

    unsafe fn pointer_to_string(pointer: *const u8) -> String {
        let mut buffer: Vec<u8> = Vec::new();
        let mut curr = pointer;
        while *curr != 0 {
            buffer.push(*curr);
            curr = curr.add(1);
        }
        std::str::from_utf8(&buffer[..]).unwrap().to_string()
    }

    pub fn load(path: &String) -> Result<LibraryCache, String> {
        let mut library_cache = LibraryCache::new();
        let mut result = Result::Err("Unable to load cache".to_string());
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
                    println!("Magic number len: {}", cache_magic_new.len());
                    println!("Version len: {}", cache_version.len());
                    elem_ptr = elem_ptr.offset(cache_version.len() as isize);
                    let number_of_entries: u32 = ptr::read_unaligned(elem_ptr as *const _);
                    elem_ptr = elem_ptr.offset(size_of::<u32>() as isize);
                    let string_table_size: u32 = ptr::read_unaligned(elem_ptr as *const _);
                    elem_ptr = elem_ptr.offset((size_of::<u32>() * 6) as isize);
                    let entries_offset = (elem_ptr as u64) - (file_ptr as u64);
                    println!("Entries start at offset: {}", entries_offset);
                    println!("Number of cache entries: {}", number_of_entries);
                    println!("String table size: {}", string_table_size);
                    let mut cache_entries: Vec<CacheEntry> = Vec::new();
                    for _ in 0..number_of_entries {
                        let entry: CacheEntry = ptr::read_unaligned(elem_ptr as * const _);
                        cache_entries.push(entry.clone());
                        elem_ptr = elem_ptr.offset(size_of::<CacheEntry>() as isize);
                    }
                    let string_table_offset = (elem_ptr as u64) - (file_ptr as u64);
                    println!("String table starts at offset: {:#X}", string_table_offset);
                    for entry in cache_entries.iter() {
                        let key_string_pointer = file_ptr.offset(entry.key as isize);
                        let value_string_pointer = file_ptr.offset(entry.value as isize);
                        let key = LibraryCache::pointer_to_string(key_string_pointer as *const u8);
                        let value = LibraryCache::pointer_to_string(value_string_pointer as *const u8);
                        library_cache.cache.insert(key, value);
                    }
                    syscall::munmap(file_ptr, file_size as size_t);
                    result = Ok(library_cache);
                } else {
                    result = Result::Err("Unable to mmap file".to_string());
                }
                syscall::close(file_descriptor);
            }
        }
        result
    }
}
