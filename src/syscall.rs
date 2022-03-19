use std::ffi::CString;
use std::{mem, ptr};

extern "C" {
    pub fn mmap(
        address: *const libc::c_void,
        length: libc::size_t,
        protection: i32,
        flags: i32,
        file_descriptor: i32,
        offset: libc::off_t,
    ) -> *const libc::c_void;

    pub fn munmap(address: *const libc::c_void, length: libc::size_t) -> i32;

    pub fn open(pathname: *const libc::c_char, flags: i32) -> i32;

    pub fn close(file_descriptor: i32) -> i32;

    pub fn clone(
        entry: *const libc::c_void,
        stack: *const libc::c_void,
        flags: i32,
        arg: *const libc::c_void,
        parent_thread_identifier: *const libc::pid_t,
        thread_local_storage: *const libc::c_void,
        child_thread_identifier: *const libc::c_void,
    ) -> i32;

    pub fn wait(status: *const i32);

    pub fn fstat(file_descriptor: i32, result: *const libc::stat) -> i32;
}

pub fn get_file_size(descriptor: i32) -> i64 {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(mem::size_of::<libc::stat>(), 0);
    unsafe {
        fstat(descriptor, buffer.as_ptr() as *const libc::stat);
    }
    let file_info: libc::stat = unsafe { ptr::read(buffer.as_ptr() as *const _) };
    file_info.st_size
}

pub fn open_file(file_path: &String) -> Result<i32, String> {
    let file_path_c_string = CString::new(file_path.clone()).unwrap();
    let file_descriptor = unsafe { open(file_path_c_string.as_ptr(), libc::O_RDONLY) };
    if file_descriptor < 0 {
        Result::Err(format!("Unable to open file {}", file_path))
    } else {
        Result::Ok(file_descriptor)
    }
}
