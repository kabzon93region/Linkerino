#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <cstdint>
#include <string>

namespace linkerino {

class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE value) : handle_(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : handle_(other.handle_) { other.handle_ = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~Handle() { Close(); }

    void Close() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            ::CloseHandle(handle_);
        }
        handle_ = INVALID_HANDLE_VALUE;
    }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }
    HANDLE get() const { return handle_; }
    HANDLE* out() {
        Close();
        return &handle_;
    }
    void Reset(HANDLE value) {
        Close();
        handle_ = value;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

std::wstring Win32ErrorText(DWORD code);
std::wstring TrimPathInput(const std::wstring& value);
std::wstring JoinPath(const std::wstring& dir, const std::wstring& leaf);
std::wstring LeafName(const std::wstring& path);
std::wstring ParentPath(const std::wstring& path);
std::wstring ApiPath(const std::wstring& plain);
std::wstring StripLongPrefix(const std::wstring& path);
bool PathExists(const std::wstring& plain);
DWORD PathAttributes(const std::wstring& plain);
std::wstring CanonicalPath(const std::wstring& plain, DWORD* error);
bool PathsEqual(const std::wstring& a, const std::wstring& b);
bool IsUnderOrEqual(const std::wstring& child, const std::wstring& parent);
bool IsLocalNtfs(const std::wstring& plain, std::wstring& error);
std::wstring VolumeRootOf(const std::wstring& plain);
std::wstring NewGuidString();
std::uint64_t FileTimeToU64(const FILETIME& value);
std::wstring ExeDirectory();
void LogLine(const std::wstring& line);
std::wstring JournalDirectory();
bool CreateSymlinkCompat(const std::wstring& link, const std::wstring& target, std::wstring& error,
                         DWORD* error_code = nullptr);
bool CreateSymlinkRaw(const std::wstring& link, const std::wstring& target, bool directory, std::wstring& error,
                      DWORD* error_code = nullptr);
DWORD WindowsBuildNumber();
std::string ToUtf8(const std::wstring& text);
std::wstring FromUtf8(const std::string& text);

struct FsCapabilities {
    std::wstring file_system;
    bool remote = false;
    bool supports_acl = false;
    bool supports_streams = false;
    bool supports_reparse = false;
    bool supports_hardlinks = false;
    bool checks_creation_time = true;
    bool supports_dir_streams = false;
    DWORD time_tolerance_ms = 0;
    DWORD attribute_mask = 0;
};

bool CheckVolumeSupported(const std::wstring& plain, std::wstring& error);
FsCapabilities ProbeFilesystem(const std::wstring& parent, std::wstring& error);

}  // namespace linkerino
