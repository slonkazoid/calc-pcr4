use libc::*;

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn by_partuuid(id: &str) -> io::Result<Option<PathBuf>> {
    by_dev(PathBuf::from("/dev/disk/by-partuuid").join(id))
}

pub fn by_dev(path: impl AsRef<Path>) -> io::Result<Option<PathBuf>> {
    let path = std::fs::canonicalize(path)?;
    unsafe {
        let path_cstring =
            CString::from_vec_unchecked(Vec::from(path.as_os_str().as_encoded_bytes()));

        let mounts_file = setmntent(c"/proc/mounts".as_ptr(), c"r".as_ptr());
        if mounts_file.is_null() {
            return Err(io::Error::from_raw_os_error(*__errno_location()));
        }

        loop {
            let entry = getmntent(mounts_file);
            if entry.is_null() {
                return Err(io::Error::from_raw_os_error(*__errno_location()));
            }
            let entry = *entry;

            let dev = CStr::from_ptr(entry.mnt_fsname);

            if dev == path_cstring.as_c_str() {
                let mount_point = OsStr::from_bytes(CStr::from_ptr(entry.mnt_dir).to_bytes());
                return Ok(Some(PathBuf::from(mount_point)));
            };
        }
    }
}
