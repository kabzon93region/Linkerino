//! Thin, explicit Win32 layer: long paths, filesystem capabilities, ACLs,
//! streams, reparse points and volume helpers.

#![allow(non_snake_case)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF,
    ERROR_MORE_DATA, ERROR_SUCCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::{
    ACL, GetAce, GetAclInformation, GetSecurityDescriptorControl, ACL_SIZE_INFORMATION, ACL_REVISION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED,
};

pub const SE_FILE_OBJECT: i32 = 1;
pub type Pacl = *mut ACL;
const GENERIC_WRITE: u32 = 0x4000_0000;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, DeleteFileW, FileStreamInfo, FlushFileBuffers, GetDiskFreeSpaceExW, GetDriveTypeW,
    GetFileAttributesW, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetVolumeInformationW, GetVolumePathNameW, MoveFileExW, SetFileAttributesW, SetFileTime, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_WRITE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

pub const INVALID: HANDLE = INVALID_HANDLE_VALUE;

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
    let mut buffer = vec![0u16; 1024];
    let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    close(handle);
    if length == 0 || length as usize >= buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    let text = String::from_utf16_lossy(&buffer);
    Some(strip_long_prefix(&text))
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

pub fn file_info(path: &str, no_follow: bool) -> Option<FileId> {
    let flags = FILE_FLAG_BACKUP_SEMANTICS | if no_follow { FILE_FLAG_OPEN_REPARSE_POINT } else { 0 };
    let handle = open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      OPEN_EXISTING, flags);
    if handle == INVALID {
        return None;
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    close(handle);
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
    loop {
        let info = unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_STREAM_INFO) };
        let name_units = (info.StreamNameLength / 2) as usize;
        let name: String = unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(info.StreamName.as_ptr(), name_units))
        };
        if name != "::$DATA" {
            let mut clean = name.clone();
            if clean.starts_with(':') {
                clean.remove(0);
            }
            if let Some(stripped) = clean.strip_suffix(":$DATA") {
                clean = stripped.to_string();
            }
            result.push(StreamInfo { name: clean, size: info.StreamSize as u64 });
        }
        if info.NextEntryOffset == 0 {
            break;
        }
        offset += info.NextEntryOffset as usize;
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

fn read_unicode(raw: &[u8], base: usize, offset: usize, length: usize) -> String {
    if length == 0 || offset + length > raw.len().saturating_sub(base) {
        return String::new();
    }
    let start = base + offset;
    let units: Vec<u16> =
        unsafe { std::slice::from_raw_parts(raw[start..].as_ptr() as *const u16, length / 2) }.to_vec();
    String::from_utf16_lossy(&units)
}

pub fn read_reparse(path: &str) -> Result<Reparse, u32> {
    let handle = open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    if handle == INVALID {
        return Err(last_error());
    }
    let mut buffer = vec![0u8; 16 * 1024];
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, std::ptr::null(), 0, buffer.as_mut_ptr() as *mut _,
                        buffer.len() as u32, &mut returned, std::ptr::null_mut())
    };
    close(handle);
    if ok == 0 {
        return Err(last_error());
    }
    buffer.truncate(returned as usize);
    if buffer.len() < 8 {
        return Err(0);
    }
    let tag = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let (_base, substitute, relative) = if tag == IO_REPARSE_TAG_SYMLINK && buffer.len() >= 20 {
        let offset = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
        let length = u16::from_le_bytes([buffer[10], buffer[11]]) as usize;
        let flags = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
        (20usize, read_unicode(&buffer, 20, offset, length), (flags & 1) != 0)
    } else if tag == IO_REPARSE_TAG_MOUNT_POINT && buffer.len() >= 16 {
        let offset = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
        let length = u16::from_le_bytes([buffer[10], buffer[11]]) as usize;
        (16usize, read_unicode(&buffer, 16, offset, length), false)
    } else {
        return Err(0);
    };
    Ok(Reparse { tag, substitute, relative, raw: buffer })
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

fn acl_signature_from(acl: Pacl) -> String {
    if acl.is_null() {
        return "<null>".to_string();
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    let ok = unsafe {
        GetAclInformation(acl, &mut info as *mut _ as *mut _, size, windows_sys::Win32::Security::AclSizeInformation)
    };
    if ok == 0 {
        return "<unreadable>".to_string();
    }
    let mut signature = String::new();
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return "<unreadable-ace>".to_string();
        }
        let header = unsafe { &*(ace as *const windows_sys::Win32::Security::ACE_HEADER) };
        let flags = header.AceFlags & !0x10;
        signature.push_str(&format!("{}|{}|", header.AceType, flags));
        match header.AceType {
            0 | 1 => {
                let allowed = unsafe { &*(ace as *const windows_sys::Win32::Security::ACCESS_ALLOWED_ACE) };
                let sid = unsafe { (ace as *const u8).add(8) } as *mut std::ffi::c_void;
                signature.push_str(&format!("{}|{};", allowed.Mask, sid_text(sid)));
            }
            _ => signature.push_str("opaque;"),
        }
    }
    signature
}

fn sid_text(sid: *mut std::ffi::c_void) -> String {
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    let ok = unsafe { windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut text) };
    if ok == 0 || text.is_null() {
        return "?".to_string();
    }
    let mut length = 0usize;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe {
        LocalFree(text as *mut _);
    }
    result
}

pub fn acl_signature(path: &str) -> Option<String> {
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
    let signature = acl_signature_from(acl);
    unsafe {
        LocalFree(descriptor as *mut _);
    }
    Some(signature)
}

pub fn apply_acl(source: &str, target: &str) -> bool {
    let source_name = api(source);
    let mut acl: Pacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(source_name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(),
                              std::ptr::null_mut(), &mut acl, std::ptr::null_mut(), &mut descriptor)
    };
    if result != ERROR_SUCCESS as u32 {
        return false;
    }
    if acl.is_null() {
        // A source without a DACL (NULL) must stay NULL, but protected against inheritance.
        let mut target_name = api(target);
        let result = unsafe {
            SetNamedSecurityInfoW(target_name.as_mut_ptr(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                  std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                                  std::ptr::null_mut())
        };
        unsafe { LocalFree(descriptor as *mut _) };
        return result == ERROR_SUCCESS as u32;
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    if unsafe {
        GetAclInformation(acl, &mut info as *mut _ as *mut _, size,
                          windows_sys::Win32::Security::AclSizeInformation)
    } == 0
    {
        unsafe { LocalFree(descriptor as *mut _) };
        return false;
    }
    // Copy the ACEs into a fresh protected ACL so the target does not inherit extra rights.
    // The buffer is a Vec<u32> so the ACL always stays 4-byte aligned.
    let capacity = (info.AclBytesInUse + 512 + 3) & !3;
    let mut storage = vec![0u32; (capacity as usize) / 4];
    let built = storage.as_mut_ptr() as Pacl;
    if unsafe { windows_sys::Win32::Security::InitializeAcl(built, capacity, ACL_REVISION) } == 0 {
        unsafe { LocalFree(descriptor as *mut _) };
        return false;
    }
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            continue;
        }
        let header = unsafe { &*(ace as *const windows_sys::Win32::Security::ACE_HEADER) };
        if (header.AceSize as usize) < std::mem::size_of::<windows_sys::Win32::Security::ACE_HEADER>() {
            continue;
        }
        let mut bytes = unsafe { std::slice::from_raw_parts(ace as *const u8, header.AceSize as usize) }.to_vec();
        // ACE_HEADER layout: AceType (0), AceFlags (1), AceSize (2..4). Drop only the inherited flag.
        bytes[1] &= !0x10;
        let added = unsafe {
            windows_sys::Win32::Security::AddAce(built, ACL_REVISION, u32::MAX, bytes.as_ptr() as *const _,
                                                 header.AceSize as u32)
        };
        if added == 0 {
            unsafe { LocalFree(descriptor as *mut _) };
            return false;
        }
    }
    let mut target_name = api(target);
    let result = unsafe {
        SetNamedSecurityInfoW(target_name.as_mut_ptr(), SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              std::ptr::null_mut(), std::ptr::null_mut(), built, std::ptr::null_mut())
    };
    unsafe { LocalFree(descriptor as *mut _) };
    result == ERROR_SUCCESS as u32
}

pub fn dacl_protected(path: &str) -> bool {
    let name = api(path);
    let mut acl: Pacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(),
                              std::ptr::null_mut(), &mut acl, std::ptr::null_mut(), &mut descriptor)
    };
    if result != ERROR_SUCCESS as u32 {
        return false;
    }
    let mut control: SECURITY_DESCRIPTOR_CONTROL = 0;
    let mut revision: u32 = 0;
    let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    unsafe {
        LocalFree(descriptor as *mut _);
    }
    ok != 0 && (control & SE_DACL_PROTECTED) != 0
}

pub fn volume_root(path: &str) -> Option<String> {
    let name = api(path);
    let mut buffer = vec![0u16; 512];
    let ok = unsafe { GetVolumePathNameW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if ok == 0 {
        return None;
    }
    let length = buffer.iter().position(|v| *v == 0).unwrap_or(buffer.len());
    Some(strip_long_prefix(&String::from_utf16_lossy(&buffer[..length])))
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

pub fn flush_volume(path: &str) -> bool {
    let Some(root) = volume_root(path) else { return false };
    let device = format!("\\\\.\\{}", root.chars().take(2).collect::<String>());
    // Device paths must reach CreateFileW as written: a `\\?\` prefix turns `\\.\C:` into a bad name.
    let name = wide(&device);
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

pub fn create_dir(path: &str) -> bool {
    let name = api(path);
    let ok = unsafe { windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(name.as_ptr(), std::ptr::null()) };
    ok != 0 || last_error() == ERROR_ALREADY_EXISTS
}

pub fn path_exists(path: &str) -> bool {
    !path.is_empty() && exists(path)
}

pub fn parent(path: &str) -> String {
    match Path::new(path).parent() {
        Some(value) => value.to_string_lossy().to_string(),
        None => String::new(),
    }
}

pub fn leaf(path: &str) -> String {
    Path::new(path).file_name().map(|v| v.to_string_lossy().to_string()).unwrap_or_default()
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

pub const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
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
