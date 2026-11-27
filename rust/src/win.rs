//! Thin, explicit Win32 layer: long paths, filesystem capabilities, ACLs,
//! streams, reparse points and volume helpers.

#![allow(non_snake_case)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF,
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_NOT_SUPPORTED, ERROR_SUCCESS, FILETIME,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Globalization::CompareStringOrdinal;
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, GetAce, GetAclInformation, GetSecurityDescriptorControl, ACE_HEADER, ACL_REVISION,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED,
};

pub const SE_FILE_OBJECT: i32 = 1;
pub type Pacl = *mut ACL;
const GENERIC_WRITE: u32 = 0x4000_0000;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, DeleteFileW, FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx,
    FileStreamInfo, FlushFileBuffers, GetDiskFreeSpaceExW, GetDriveTypeW, GetFileAttributesW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, MoveFileExW, SetFileAttributesW, SetFileInformationByHandle,
    SetFileTime, BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO,
    FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

pub const INVALID: HANDLE = INVALID_HANDLE_VALUE;

/// Access rights used by the guarded delete path.
pub const DELETE_ACCESS: u32 = 0x0001_0000;
pub const READ_DATA_ACCESS: u32 = 0x0001;
pub const READ_ATTRIBUTES_ACCESS: u32 = 0x0000_0080;
pub const WRITE_ATTRIBUTES_ACCESS: u32 = 0x0000_0100;
pub const WRITE_DAC_ACCESS: u32 = 0x0004_0000;

pub fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(std::iter::once(0)).collect()
}

/// Converts a plain path to an extended-length path understood by every API.
pub fn api(path: &str) -> Vec<u16> {
    if path.starts_with("\\\\?\\") {
        return wide(path);
    }
    if path.starts_with("\\\\") {
        return wide(&format!("\\\\?\\UNC\\{}", &path[2..]));
    }
    wide(&format!("\\\\?\\{}", path))
}

pub fn strip_long_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        return format!("\\\\{}", rest);
    }
    if let Some(rest) = path.strip_prefix("\\\\?\\") {
        return rest.to_string();
    }
    path.to_string()
}

fn file_time_to_u64(value: &FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn u64_to_file_time(value: u64) -> FILETIME {
    FILETIME { dwLowDateTime: value as u32, dwHighDateTime: (value >> 32) as u32 }
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn open(path: &str, access: u32, share: u32, disposition: u32, flags: u32) -> HANDLE {
    let name = api(path);
    unsafe { CreateFileW(name.as_ptr(), access, share, std::ptr::null(), disposition, flags, std::ptr::null_mut()) }
}

pub fn close(handle: HANDLE) {
    if handle != INVALID && !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

pub fn exists(path: &str) -> bool {
    let name = api(path);
    unsafe { GetFileAttributesW(name.as_ptr()) != u32::MAX }
}

pub fn attributes(path: &str) -> Option<u32> {
    let name = api(path);
    let value = unsafe { GetFileAttributesW(name.as_ptr()) };
    if value == u32::MAX {
        None
    } else {
        Some(value)
    }
}

pub fn set_attributes(path: &str, attrs: u32) -> bool {
    let name = api(path);
    unsafe { SetFileAttributesW(name.as_ptr(), attrs) != 0 }
}

pub fn delete_file(path: &str) -> bool {
    let name = api(path);
    unsafe { DeleteFileW(name.as_ptr()) != 0 }
}

pub fn delete_dir(path: &str) -> bool {
    let name = api(path);
    unsafe { windows_sys::Win32::Storage::FileSystem::RemoveDirectoryW(name.as_ptr()) != 0 }
}

pub fn move_path(from: &str, to: &str, replace: bool) -> bool {
    let from_name = api(from);
    let to_name = api(to);
    let flags = if replace { MOVEFILE_REPLACE_EXISTING } else { 0 };
    unsafe { MoveFileExW(from_name.as_ptr(), to_name.as_ptr(), flags) != 0 }
}

pub fn canonical(path: &str) -> Option<String> {
    let handle = open(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS);
    if handle == INVALID {
        return None;
    }
    let mut size = 512usize;
    let mut text = None;
    // The final path can be longer than the input: grow the buffer until the API fits into it.
    while size <= 32 * 1024 {
        let mut buffer = vec![0u16; size];
        let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
        if length == 0 {
            break;
        }
        if (length as usize) < buffer.len() {
            buffer.truncate(length as usize);
            // Strict: a substituted character would open a different object than the user chose.
            text = String::from_utf16(&buffer).ok().map(|value| strip_long_prefix(&value));
            break;
        }
        size = (length as usize) + 1;
    }
    close(handle);
    text
}

/// Compares two paths the way NTFS compares names: case-insensitively by the Windows upcase table.
pub fn equal_paths(left: &str, right: &str) -> bool {
    let left_wide = wide(left);
    let right_wide = wide(right);
    let result = unsafe {
        CompareStringOrdinal(left_wide.as_ptr(), (left_wide.len() - 1) as i32, right_wide.as_ptr(),
                             (right_wide.len() - 1) as i32, 1)
    };
    result == 2 // CSTR_EQUAL
}

/// True when `child` lies inside `parent`. Compares byte slices, so a multi-byte character can
/// never be cut in half.
pub fn under_prefix(child: &str, parent: &str) -> bool {
    if parent.is_empty() || child.len() <= parent.len() {
        return false;
    }
    let child_bytes = child.as_bytes();
    let parent_bytes = parent.as_bytes();
    if !child_bytes[..parent_bytes.len()].eq_ignore_ascii_case(parent_bytes) {
        return false;
    }
    let next = child_bytes[parent_bytes.len()];
    parent_bytes.ends_with(b"\\") || next == b'\\'
}

pub struct FileId {
    pub serial: u64,
    pub index: u64,
    pub links: u32,
    pub created: u64,
    pub modified: u64,
    pub attrs: u32,
    pub size: u64,
}

/// Stable identity of one object on one volume. Re-checked before every change.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Hash)]
pub struct ObjectId {
    pub serial: u64,
    pub index: u64,
}

impl FileId {
    pub fn id(&self) -> ObjectId {
        ObjectId { serial: self.serial, index: self.index }
    }
}

fn info_of(handle: HANDLE) -> Option<FileId> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return None;
    }
    Some(FileId {
        serial: info.dwVolumeSerialNumber as u64,
        index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        links: info.nNumberOfLinks,
        created: file_time_to_u64(&info.ftCreationTime),
        modified: file_time_to_u64(&info.ftLastWriteTime),
        attrs: info.dwFileAttributes,
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
    })
}

pub fn file_info(path: &str, no_follow: bool) -> Option<FileId> {
    let flags = FILE_FLAG_BACKUP_SEMANTICS | if no_follow { FILE_FLAG_OPEN_REPARSE_POINT } else { 0 };
    let handle = open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      OPEN_EXISTING, flags);
    if handle == INVALID {
        return None;
    }
    let info = info_of(handle);
    close(handle);
    info
}

pub fn object_id(path: &str, no_follow: bool) -> Option<ObjectId> {
    file_info(path, no_follow).map(|info| info.id())
}

/// An owned handle. Every check and the change that follows run on the same object, so a name
/// that is swapped after the check cannot redirect the change.
pub struct Guard {
    handle: HANDLE,
}

impl Guard {
    pub fn open(path: &str, access: u32, follow_reparse: bool) -> Result<Guard, u32> {
        let flags = FILE_FLAG_BACKUP_SEMANTICS | if follow_reparse { 0 } else { FILE_FLAG_OPEN_REPARSE_POINT };
        let handle = open(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, flags);
        if handle == INVALID {
            Err(last_error())
        } else {
            Ok(Guard { handle })
        }
    }

    /// Opens an object for a change that must not be renamed meanwhile: the handle is shared for
    /// read and write only, so the name cannot be moved or replaced while it is held.
    pub fn open_held(path: &str, access: u32) -> Result<Guard, u32> {
        let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
        let handle = open(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, flags);
        if handle == INVALID {
            Err(last_error())
        } else {
            Ok(Guard { handle })
        }
    }

    /// Creates a new file and keeps it open with no sharing, so nothing else can read it while
    /// the data is being written. `write_dac` asks for the right to apply the source DACL before
    /// the handle is closed.
    pub fn open_new(path: &str, write_dac: bool) -> Result<Guard, u32> {
        let name = api(path);
        let access = GENERIC_WRITE | FILE_WRITE_ATTRIBUTES | if write_dac { WRITE_DAC_ACCESS } else { 0 };
        let handle = unsafe {
            CreateFileW(name.as_ptr(), access, 0, std::ptr::null(), 1 /* CREATE_NEW */, 0x80 /* NORMAL */,
                        std::ptr::null_mut())
        };
        if handle == INVALID {
            Err(last_error())
        } else {
            Ok(Guard { handle })
        }
    }

    pub fn info(&self) -> Option<FileId> {
        info_of(self.handle)
    }

    pub fn id(&self) -> Option<ObjectId> {
        info_of(self.handle).map(|info| info.id())
    }

    /// Borrows the handle as a `File`; the guard keeps ownership, so this never closes it twice.
    pub fn as_file(&self) -> std::mem::ManuallyDrop<std::fs::File> {
        unsafe {
            std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(
                self.handle as std::os::windows::io::RawHandle,
            ))
        }
    }

    pub fn reparse(&self) -> Result<Reparse, u32> {
        reparse_of_handle(self.handle)
    }

    pub fn set_basic(&self, created: u64, modified: u64, accessed: u64, attrs: Option<u32>) -> bool {
        let mut basic = FILE_BASIC_INFO {
            CreationTime: created as i64,
            LastAccessTime: accessed as i64,
            LastWriteTime: modified as i64,
            ChangeTime: 0,
            FileAttributes: 0,
        };
        if let Some(value) = attrs {
            basic.FileAttributes = value;
        } else if let Some(info) = info_of(self.handle) {
            basic.FileAttributes = info.attrs;
        }
        set_basic_info(self.handle, &basic)
    }

    pub fn set_dacl_from(&self, source: &str) -> bool {
        copy_dacl_to_handle(source, self.handle)
    }

    pub fn sync(&self) -> bool {
        unsafe { FlushFileBuffers(self.handle) != 0 }
    }

    /// Marks this exact object for deletion. POSIX semantics remove the name immediately and ignore
    /// a read-only attribute; older systems fall back to delete-on-close.
    pub fn remove(&mut self) -> Result<(), u32> {
        delete_by_handle(self.handle)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        close(self.handle);
    }
}

fn set_basic_info(handle: HANDLE, basic: &FILE_BASIC_INFO) -> bool {
    let ok = unsafe {
        SetFileInformationByHandle(handle, FileBasicInfo, basic as *const FILE_BASIC_INFO as *const _,
                                   std::mem::size_of::<FILE_BASIC_INFO>() as u32)
    };
    ok != 0
}

fn delete_by_handle(handle: HANDLE) -> Result<(), u32> {
    let mut modern = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let ok = unsafe {
        SetFileInformationByHandle(handle, FileDispositionInfoEx, &mut modern as *mut _ as *const _,
                                   std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32)
    };
    if ok != 0 {
        return Ok(());
    }
    let code = last_error();
    if code != ERROR_INVALID_PARAMETER && code != ERROR_NOT_SUPPORTED && code != ERROR_INVALID_FUNCTION {
        return Err(code);
    }
    // Older Windows: clear the read-only attribute on this same object, then delete on close.
    let mut basic = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: 0,
    };
    let read = unsafe {
        GetFileInformationByHandleEx(handle, FileBasicInfo, &mut basic as *mut _ as *mut _,
                                     std::mem::size_of::<FILE_BASIC_INFO>() as u32)
    };
    if read != 0 {
        basic.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        set_basic_info(handle, &basic);
    }
    let mut legacy = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    let ok = unsafe {
        SetFileInformationByHandle(handle, FileDispositionInfo, &mut legacy as *mut _ as *const _,
                                   std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32)
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

pub fn set_times(path: &str, created: u64, modified: u64, accessed: u64) -> bool {
    let handle = open(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    if handle == INVALID {
        return false;
    }
    let c = u64_to_file_time(created);
    let m = u64_to_file_time(modified);
    let a = u64_to_file_time(accessed);
    let ok = unsafe { SetFileTime(handle, &c, &a, &m) };
    close(handle);
    ok != 0
}

pub fn hard_link(existing: &str, new_name: &str) -> bool {
    let from = api(existing);
    let to = api(new_name);
    unsafe { CreateHardLinkW(to.as_ptr(), from.as_ptr(), std::ptr::null()) != 0 }
}

pub fn symlink(link: &str, target: &str, directory: bool) -> Result<(), u32> {
    use windows_sys::Win32::Storage::FileSystem::{SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
                                                  SYMBOLIC_LINK_FLAG_DIRECTORY};
    let link_name = api(link);
    let target_name = if target.len() >= 248 && (target.starts_with("\\\\") || target.as_bytes().get(1) == Some(&b':'))
    {
        api(target)
    } else {
        wide(target)
    };
    let flags = if directory { SYMBOLIC_LINK_FLAG_DIRECTORY } else { 0 };
    unsafe {
        let ok = windows_sys::Win32::Storage::FileSystem::CreateSymbolicLinkW(
            link_name.as_ptr(), target_name.as_ptr(), flags | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
        if ok != 0 { Ok(()) } else { Err(GetLastError()) }
    }
}

pub struct StreamInfo {
    pub name: String,
    pub size: u64,
}

pub fn streams(path: &str) -> Result<Vec<StreamInfo>, u32> {
    let handle = open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    if handle == INVALID {
        return Err(last_error());
    }
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let ok = unsafe {
            GetFileInformationByHandleEx(handle, FileStreamInfo, buffer.as_mut_ptr() as *mut _, buffer.len() as u32)
        };
        if ok != 0 {
            break;
        }
        let code = last_error();
        if code == ERROR_HANDLE_EOF || code == ERROR_FILE_NOT_FOUND {
            close(handle);
            return Ok(Vec::new());
        }
        if code == ERROR_MORE_DATA && buffer.len() < 32 * 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        close(handle);
        return Err(code);
    }
    let mut result = Vec::new();
    let mut offset = 0usize;
    // FILE_STREAM_INFO: NextEntryOffset (u32), StreamNameLength (u32), StreamSize (i64),
    // StreamAllocationSize (i64), then the UTF-16 name. The Rust type ends with
    // `StreamName: [u16; 1]`, so `size_of` is larger than the offset of the name; 24 is the
    // documented start of the name bytes.
    const STREAM_NAME_OFFSET: usize = 24;
    loop {
        const INVALID_DATA: u32 = 0x0000000D;
        let header = match buffer.get(offset..offset + STREAM_NAME_OFFSET) {
            Some(value) => value,
            None => {
                close(handle);
                return Err(INVALID_DATA);
            }
        };
        let next = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let name_bytes = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let size = u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14], header[15],
        ]);
        let name_start = offset + STREAM_NAME_OFFSET;
        let name_end = match name_start.checked_add(name_bytes) {
            Some(value) if value <= buffer.len() && name_bytes % 2 == 0 => value,
            _ => {
                close(handle);
                return Err(INVALID_DATA);
            }
        };
        let units: Vec<u16> = buffer[name_start..name_end].chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name = match String::from_utf16(&units) {
            Ok(value) => value,
            Err(_) => {
                close(handle);
                return Err(INVALID_DATA);
            }
        };
        if name != "::$DATA" {
            let mut clean = name.clone();
            if clean.starts_with(':') {
                clean.remove(0);
            }
            if let Some(stripped) = clean.strip_suffix(":$DATA") {
                clean = stripped.to_string();
            }
            result.push(StreamInfo { name: clean, size });
        }
        if next == 0 {
            break;
        }
        offset = match offset.checked_add(next) {
            Some(value) if value < buffer.len() => value,
            _ => {
                close(handle);
                return Err(INVALID_DATA);
            }
        };
    }
    close(handle);
    Ok(result)
}

const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
const FSCTL_GET_REPARSE_POINT: u32 = 0x000900A8;
const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;

pub struct Reparse {
    pub tag: u32,
    pub substitute: String,
    pub relative: bool,
    pub raw: Vec<u8>,
}

fn read_unicode(raw: &[u8], base: usize, offset: usize, length: usize) -> Result<String, u32> {
    // 0x1B: ERROR_INVALID_DATA - a malformed reparse buffer must never be read past its end.
    const INVALID_DATA: u32 = 0x0000000D;
    if length % 2 != 0 {
        return Err(INVALID_DATA);
    }
    let end = base.checked_add(offset).and_then(|start| start.checked_add(length)).ok_or(INVALID_DATA)?;
    if end > raw.len() {
        return Err(INVALID_DATA);
    }
    let start = base + offset;
    let units: Vec<u16> = raw[start..end].chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    // A lossy conversion would silently point the link at another object.
    String::from_utf16(&units).map_err(|_| INVALID_DATA)
}

fn reparse_of_handle(handle: HANDLE) -> Result<Reparse, u32> {
    let mut buffer = vec![0u8; 16 * 1024];
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, std::ptr::null(), 0, buffer.as_mut_ptr() as *mut _,
                        buffer.len() as u32, &mut returned, std::ptr::null_mut())
    };
    if ok == 0 {
        return Err(last_error());
    }
    let used = (returned as usize).min(buffer.len());
    parse_reparse(&buffer[..used])
}

fn parse_reparse(buffer: &[u8]) -> Result<Reparse, u32> {
    const INVALID_DATA: u32 = 0x0000000D;
    if buffer.len() < 8 {
        return Err(INVALID_DATA);
    }
    let tag = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    // ReparseDataLength counts only the data that follows the 8-byte header, so the full block is
    // 8 + length. Treating it as the whole size used to cut the last 8 bytes off a junction.
    let data_length = u16::from_le_bytes([buffer[4], buffer[5]]) as usize;
    let total = 8usize.checked_add(data_length).ok_or(INVALID_DATA)?;
    if total > buffer.len() {
        return Err(INVALID_DATA);
    }
    let (base, substitute, relative) = if tag == IO_REPARSE_TAG_SYMLINK {
        // Tag header: 4 offsets/lengths (8 bytes) + flags (4 bytes).
        if total < 20 {
            return Err(INVALID_DATA);
        }
        let offset = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
        let length = u16::from_le_bytes([buffer[10], buffer[11]]) as usize;
        let flags = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
        (20usize, read_unicode(&buffer[..total], 20, offset, length)?, (flags & 1) != 0)
    } else if tag == IO_REPARSE_TAG_MOUNT_POINT {
        // Tag header: 4 offsets/lengths (8 bytes), no flags.
        if total < 16 {
            return Err(INVALID_DATA);
        }
        let offset = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
        let length = u16::from_le_bytes([buffer[10], buffer[11]]) as usize;
        (16usize, read_unicode(&buffer[..total], 16, offset, length)?, false)
    } else {
        return Err(INVALID_DATA);
    };
    let _ = base;
    Ok(Reparse { tag, substitute, relative, raw: buffer[..total].to_vec() })
}

pub fn read_reparse(path: &str) -> Result<Reparse, u32> {
    let guard = Guard::open(path, FILE_READ_ATTRIBUTES, false)?;
    guard.reparse()
}

/// Builds a mount-point (junction) reparse block that points at `target`.
/// Used when the original junction pointed inside the moved folder and must be redirected.
pub fn junction_block(target: &str) -> Vec<u8> {
    let substitute = format!("\\??\\{}", target);
    let substitute_units: Vec<u16> = substitute.encode_utf16().collect();
    let print_units: Vec<u16> = target.encode_utf16().collect();
    // Windows counts the name bytes without the terminating NUL, then writes one extra NUL word
    // after each name: fields, substitute, NUL, print, NUL.
    let substitute_len = (substitute_units.len() * 2) as u16;
    let print_len = (print_units.len() * 2) as u16;
    let print_offset = substitute_len.saturating_add(2);
    let data_len = 8u16
        .saturating_add(substitute_len)
        .saturating_add(2)
        .saturating_add(print_len)
        .saturating_add(2);
    let mut block = Vec::with_capacity(8 + data_len as usize);
    block.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    block.extend_from_slice(&data_len.to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    block.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    block.extend_from_slice(&substitute_len.to_le_bytes());
    block.extend_from_slice(&print_offset.to_le_bytes());
    block.extend_from_slice(&print_len.to_le_bytes());
    for unit in substitute_units {
        block.extend_from_slice(&unit.to_le_bytes());
    }
    block.extend_from_slice(&0u16.to_le_bytes());
    for unit in print_units {
        block.extend_from_slice(&unit.to_le_bytes());
    }
    block.extend_from_slice(&0u16.to_le_bytes());
    block
}

pub fn write_junction(dir: &str, raw: &[u8]) -> bool {
    let handle = open(dir, GENERIC_WRITE, 0, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    if handle == INVALID {
        return false;
    }
    let mut data = raw.to_vec();
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, data.as_mut_ptr() as *mut _, data.len() as u32,
                        std::ptr::null_mut(), 0, &mut returned, std::ptr::null_mut())
    };
    close(handle);
    ok != 0
}

pub fn normalize_target(target: &str) -> String {
    if let Some(rest) = target.strip_prefix("\\??\\") {
        return strip_long_prefix(rest);
    }
    if let Some(rest) = target.strip_prefix("UNC\\") {
        return format!("\\\\{}", rest);
    }
    strip_long_prefix(target)
}

/// Canonical signature of a DACL. Hashing every ACE's raw bytes covers the mask, the SID and every
/// other ACE kind, so two different ACLs cannot collapse into one short signature.
fn acl_signature_from(acl: Pacl) -> String {
    use sha2::{Digest, Sha256};
    if acl.is_null() {
        return "none".to_string();
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    let ok = unsafe {
        GetAclInformation(acl, &mut info as *mut _ as *mut _, size, windows_sys::Win32::Security::AclSizeInformation)
    };
    if ok == 0 {
        return "unreadable".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"acl-v1");
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return "unreadable".to_string();
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        let ace_size = header.AceSize as usize;
        if ace_size < std::mem::size_of::<ACE_HEADER>() || ace_size > 64 * 1024 {
            return "unreadable".to_string();
        }
        let bytes = unsafe { std::slice::from_raw_parts(ace as *const u8, ace_size) };
        let mut normalized = bytes.to_vec();
        // ACE_HEADER layout: AceType (0), AceFlags (1), AceSize (2..4). Dropping only the inherited
        // flag makes an inherited ACE and the same ACE copied as explicit compare equal.
        normalized[1] &= !0x10;
        hasher.update((ace_size as u32).to_le_bytes());
        hasher.update(&normalized);
    }
    format!("{:x}", hasher.finalize())
}

fn local_dacl(path: &str) -> Option<(Pacl, PSECURITY_DESCRIPTOR, bool)> {
    let name = api(path);
    let mut acl: Pacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(),
                              std::ptr::null_mut(), &mut acl, std::ptr::null_mut(), &mut descriptor)
    };
    if result != ERROR_SUCCESS as u32 {
        return None;
    }
    let mut protected = false;
    if !descriptor.is_null() {
        let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
        let mut revision: u32 = 0;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0 {
            protected = (control & SE_DACL_PROTECTED) != 0;
        }
    }
    Some((acl, descriptor, protected))
}

/// Builds a protected copy of a DACL in an aligned buffer and returns it with the storage that
/// keeps it alive: the ACEs are copied so the target does not inherit extra rights.
fn protected_copy(acl: Pacl) -> Option<Vec<u32>> {
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    if unsafe {
        GetAclInformation(acl, &mut info as *mut _ as *mut _, size,
                          windows_sys::Win32::Security::AclSizeInformation)
    } == 0
    {
        return None;
    }
    let capacity = (info.AclBytesInUse + 512 + 3) & !3;
    let mut storage = vec![0u32; (capacity as usize) / 4];
    // The buffer is a Vec<u32> so the ACL always stays 4-byte aligned.
    let built = storage.as_mut_ptr() as Pacl;
    if unsafe { windows_sys::Win32::Security::InitializeAcl(built, capacity, ACL_REVISION) } == 0 {
        return None;
    }
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return None;
        }
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        let ace_size = header.AceSize as usize;
        if ace_size < std::mem::size_of::<ACE_HEADER>() || ace_size > 64 * 1024 {
            return None;
        }
        let mut bytes = unsafe { std::slice::from_raw_parts(ace as *const u8, ace_size) }.to_vec();
        bytes[1] &= !0x10;
        let added = unsafe {
            windows_sys::Win32::Security::AddAce(built, ACL_REVISION, u32::MAX, bytes.as_ptr() as *const _,
                                                 ace_size as u32)
        };
        if added == 0 {
            return None;
        }
    }
    Some(storage)
}

pub fn acl_signature(path: &str) -> Option<String> {
    let (acl, descriptor, _) = local_dacl(path)?;
    let signature = acl_signature_from(acl);
    unsafe {
        LocalFree(descriptor as *mut _);
    }
    Some(signature)
}

/// True when the DACL carries at least one ACE that was set explicitly rather than inherited.
/// Returns `None` when the DACL cannot be read: "unknown" must never look like "nothing to lose".
pub fn acl_has_explicit(path: &str) -> Option<bool> {
    let (acl, descriptor, _) = local_dacl(path)?;
    let mut explicit = false;
    let mut readable = true;
    if !acl.is_null() {
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
        if unsafe {
            GetAclInformation(acl, &mut info as *mut _ as *mut _, size,
                              windows_sys::Win32::Security::AclSizeInformation)
        } != 0
        {
            for index in 0..info.AceCount {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
                    readable = false;
                    break;
                }
                let header = unsafe { &*(ace as *const ACE_HEADER) };
                if (header.AceFlags & 0x10) == 0 {
                    explicit = true;
                    break;
                }
            }
        } else {
            readable = false;
        }
    }
    unsafe {
        LocalFree(descriptor as *mut _);
    }
    if readable {
        Some(explicit)
    } else {
        None
    }
}

fn set_handle_dacl(source_acl: Pacl, handle: HANDLE) -> bool {
    let result = unsafe {
        if source_acl.is_null() {
            SetSecurityInfo(handle, SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null())
        } else {
            match protected_copy(source_acl) {
                None => return false,
                Some(storage) => SetSecurityInfo(handle, SE_FILE_OBJECT,
                                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                                 std::ptr::null_mut(), std::ptr::null_mut(),
                                                 storage.as_ptr() as Pacl, std::ptr::null()),
            }
        }
    };
    result == ERROR_SUCCESS as u32
}

pub fn apply_acl(source: &str, target: &str) -> bool {
    let Some((acl, descriptor, _)) = local_dacl(source) else { return false };
    let result = unsafe {
        if acl.is_null() {
            let mut target_name = api(target);
            SetNamedSecurityInfoW(target_name.as_mut_ptr(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                  std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                                  std::ptr::null_mut())
        } else {
            match protected_copy(acl) {
                None => {
                    LocalFree(descriptor as *mut _);
                    return false;
                }
                Some(storage) => {
                    let mut target_name = api(target);
                    SetNamedSecurityInfoW(target_name.as_mut_ptr(), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                          std::ptr::null_mut(), std::ptr::null_mut(),
                                          storage.as_ptr() as Pacl, std::ptr::null_mut())
                }
            }
        }
    };
    unsafe { LocalFree(descriptor as *mut _) };
    result == ERROR_SUCCESS as u32
}

/// Applies the source DACL to an already open target handle. Used while the new file is still held
/// exclusively, so the data is never readable with the inherited (possibly wider) rights.
fn copy_dacl_to_handle(source: &str, target: HANDLE) -> bool {
    let Some((acl, descriptor, _)) = local_dacl(source) else { return false };
    let applied = set_handle_dacl(acl, target);
    unsafe { LocalFree(descriptor as *mut _) };
    applied
}

pub fn dacl_protected(path: &str) -> bool {
    local_dacl(path).map(|(_, descriptor, protected)| {
        unsafe { LocalFree(descriptor as *mut _) };
        protected
    }).unwrap_or(false)
}

pub fn volume_root(path: &str) -> Option<String> {
    let name = api(path);
    let mut buffer = vec![0u16; 512];
    let ok = unsafe { GetVolumePathNameW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if ok == 0 {
        return None;
    }
    let length = buffer.iter().position(|v| *v == 0).unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).ok().map(|value| strip_long_prefix(&value))
}

pub struct VolumeInfo {
    pub fs: String,
    pub remote: bool,
}

pub fn volume_info(path: &str) -> Option<VolumeInfo> {
    let root = volume_root(path)?;
    let root_name = wide(&root);
    let drive = unsafe { GetDriveTypeW(root_name.as_ptr()) };
    let mut fs = vec![0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(root_name.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(),
                               std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32)
    };
    if ok == 0 {
        return None;
    }
    let length = fs.iter().position(|v| *v == 0).unwrap_or(fs.len());
    Some(VolumeInfo { fs: String::from_utf16_lossy(&fs[..length]), remote: drive == 4 })
}

pub fn free_space(path: &str) -> Option<u64> {
    let root = volume_root(path)?;
    let root_name = wide(&root);
    let mut free: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(root_name.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) };
    if ok == 0 {
        None
    } else {
        Some(free)
    }
}

/// Device path of the volume that contains `path`, plus its serial number.
/// The identity comes from the mount point reported by Windows, never from the first two
/// characters of a path, so a volume mounted into a folder is handled correctly.
pub fn volume_device(path: &str) -> Option<(String, u64)> {
    let root = volume_root(path)?;
    let mut buffer = vec![0u16; 512];
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(wide(&root).as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
    };
    let device = if ok != 0 {
        let length = buffer.iter().position(|value| *value == 0).unwrap_or(buffer.len());
        String::from_utf16(&buffer[..length]).ok()?
    } else if is_drive_root(&root) {
        // Only a real drive root may fall back to `\\.\X:`; for a folder mount point the first two
        // characters name the host drive, not the volume that holds the data.
        format!("\\\\.\\{}", &root[..2])
    } else {
        return None;
    };
    let serial = volume_serial(path)?;
    Some((device, serial))
}

fn is_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2
        && bytes.len() <= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'\\')
}

pub fn volume_serial(path: &str) -> Option<u64> {
    let root = volume_root(path)?;
    let mut serial: u32 = 0;
    let ok = unsafe {
        GetVolumeInformationW(wide(&root).as_ptr(), std::ptr::null_mut(), 0, &mut serial,
                              std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0)
    };
    if ok == 0 {
        None
    } else {
        Some(serial as u64)
    }
}

/// Flushes the volume that contains `path`. Requires a volume handle, which usually needs elevation.
pub fn flush_volume(path: &str) -> bool {
    let Some((device, _)) = volume_device(path) else { return false };
    // Device paths must reach CreateFileW as written: a `\\?\` prefix turns `\\.\C:` into a bad name.
    let name = wide(&device.trim_end_matches('\\'));
    let handle = unsafe {
        CreateFileW(name.as_ptr(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(),
                    OPEN_EXISTING, 0, std::ptr::null_mut())
    };
    if handle == INVALID {
        return false;
    }
    let ok = unsafe { FlushFileBuffers(handle) };
    close(handle);
    ok != 0
}

/// Creates a directory. An existing directory counts as success only where the caller already
/// proved that the object is its own; new objects use `create_dir_new`.
pub fn create_dir(path: &str) -> bool {
    let name = api(path);
    let ok = unsafe { windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(name.as_ptr(), std::ptr::null()) };
    ok != 0 || last_error() == ERROR_ALREADY_EXISTS
}

/// Creates a directory that must not exist yet: an existing object is a failure, not a success.
pub fn create_dir_new(path: &str) -> bool {
    let name = api(path);
    unsafe { windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(name.as_ptr(), std::ptr::null()) != 0 }
}

/// Renames a path and waits until the change is recorded on disk.
pub fn move_path_through(from: &str, to: &str, replace: bool) -> bool {
    let from_name = api(from);
    let to_name = api(to);
    let flags = MOVEFILE_WRITE_THROUGH | if replace { MOVEFILE_REPLACE_EXISTING } else { 0 };
    unsafe { MoveFileExW(from_name.as_ptr(), to_name.as_ptr(), flags) != 0 }
}

pub fn path_exists(path: &str) -> bool {
    !path.is_empty() && exists(path)
}

pub fn parent(path: &str) -> String {
    // Strict: a substituted character would point at another folder.
    match Path::new(path).parent().and_then(|value| value.to_str()) {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

pub fn leaf(path: &str) -> String {
    Path::new(path).file_name().and_then(|value| value.to_str()).map(|value| value.to_string()).unwrap_or_default()
}

pub fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_string();
    }
    if name.is_empty() {
        return base.to_string();
    }
    format!("{}\\{}", base.trim_end_matches('\\'), name)
}

pub fn error_text(code: u32) -> String {
    let mut buffer = vec![0u16; 512];
    let length = unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::FormatMessageW(
            windows_sys::Win32::System::Diagnostics::Debug::FORMAT_MESSAGE_FROM_SYSTEM,
            std::ptr::null(), code, 0, buffer.as_mut_ptr(), buffer.len() as u32, std::ptr::null_mut())
    };
    let text = if length == 0 {
        String::from("unknown error")
    } else {
        String::from_utf16_lossy(&buffer[..length as usize]).trim().to_string()
    };
    format!("code {}: {}", code, text)
}

pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;

pub fn is_dir(path: &str) -> bool {
    attributes(path).map(|a| a & FILE_ATTRIBUTE_DIRECTORY != 0).unwrap_or(false)
}

pub fn is_reparse(path: &str) -> bool {
    attributes(path).map(|a| a & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(false)
}

pub fn read_whole(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

pub fn write_whole(path: &str, data: &[u8]) -> bool {
    std::fs::write(path, data).is_ok()
}
