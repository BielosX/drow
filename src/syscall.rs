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
