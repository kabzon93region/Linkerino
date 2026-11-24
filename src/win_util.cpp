#include "win_util.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <mutex>
#include <vector>

namespace linkerino {
namespace {

std::mutex g_log_mutex;
std::wstring g_log_path;
bool g_log_ready = false;

std::wstring ExePath() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, &buffer[0], static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return std::wstring();
        }
        if (length < buffer.size()) {
            buffer.resize(length);
            return buffer;
        }
        buffer.resize(buffer.size() * 2);
    }
}

bool AppendUtf8(const std::wstring& path, const std::wstring& text) {
    Handle file(CreateFileW(ApiPath(path).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }
    const std::string utf8 = ToUtf8(text);
    DWORD written = 0;
    return WriteFile(file.get(), utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr) != FALSE &&
           written == utf8.size();
}

void InitLogLocked() {
    if (g_log_ready) {
        return;
    }
    g_log_ready = true;
    const std::wstring exe_dir = ExeDirectory();
    const std::wstring beside_exe = JoinPath(exe_dir, L"Linkerino.log");
    if (AppendUtf8(beside_exe, L"")) {
        g_log_path = beside_exe;
        return;
    }
    const std::wstring local = JournalDirectory();
    if (!local.empty()) {
        g_log_path = JoinPath(local, L"Linkerino.log");
    }
}

}  // namespace

std::wstring Win32ErrorText(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring text;
    if (length != 0 && buffer != nullptr) {
        text.assign(buffer, length);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
            text.pop_back();
        }
    }
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    if (text.empty()) {
        text = L"неизвестная ошибка";
    }
    wchar_t number[32] = {0};
    swprintf_s(number, L"%lu", code);
    return std::wstring(L"код ") + number + L": " + text;
}

std::wstring TrimPathInput(const std::wstring& value) {
    std::wstring text = value;
    while (!text.empty() && (text.back() == L' ' || text.back() == L'\t' || text.back() == L'"' ||
                             text.back() == L'\r' || text.back() == L'\n')) {
        text.pop_back();
    }
    std::size_t begin = 0;
    while (begin < text.size() &&
           (text[begin] == L' ' || text[begin] == L'\t' || text[begin] == L'"' || text[begin] == L'\r' ||
            text[begin] == L'\n')) {
        ++begin;
    }
    text.erase(0, begin);
    while (text.size() > 3 && (text.back() == L'\\' || text.back() == L'/')) {
        text.pop_back();
    }
    return text;
}

std::wstring JoinPath(const std::wstring& dir, const std::wstring& leaf) {
    if (dir.empty()) {
        return leaf;
    }
    if (leaf.empty()) {
        return dir;
    }
    std::wstring result = dir;
    if (result.back() != L'\\' && result.back() != L'/') {
        result.push_back(L'\\');
    }
    result += leaf;
    return result;
}

std::wstring LeafName(const std::wstring& path) {
    std::wstring text = path;
    while (text.size() > 3 && (text.back() == L'\\' || text.back() == L'/')) {
        text.pop_back();
    }
    const std::size_t pos = text.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return text;
    }
    std::wstring leaf = text.substr(pos + 1);
    return leaf;
}

std::wstring ParentPath(const std::wstring& path) {
    std::wstring text = path;
    while (text.size() > 3 && (text.back() == L'\\' || text.back() == L'/')) {
        text.pop_back();
    }
    const std::size_t pos = text.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return std::wstring();
    }
    if (pos == 2 && text.size() > 2 && text[1] == L':') {
        return text.substr(0, 3);
    }
    return text.substr(0, pos);
}

std::wstring ApiPath(const std::wstring& plain) {
    if (plain.size() >= 4 && plain[0] == L'\\' && plain[1] == L'\\' && plain[2] == L'?' && plain[3] == L'\\') {
        return plain;
    }
    if (plain.size() >= 2 && plain[0] == L'\\' && plain[1] == L'\\') {
        return L"\\\\?\\UNC\\" + plain.substr(2);
    }
    if (plain.size() >= 2 && plain[1] == L':') {
        return L"\\\\?\\" + plain;
    }
    return plain;
}

std::wstring StripLongPrefix(const std::wstring& path) {
    if (path.size() >= 8 && path.compare(0, 8, L"\\\\?\\UNC\\") == 0) {
        return L"\\\\" + path.substr(8);
    }
    if (path.size() >= 4 && path[0] == L'\\' && path[1] == L'\\' && path[2] == L'?' && path[3] == L'\\') {
        return path.substr(4);
    }
    return path;
}

bool PathExists(const std::wstring& plain) {
    return GetFileAttributesW(ApiPath(plain).c_str()) != INVALID_FILE_ATTRIBUTES;
}

DWORD PathAttributes(const std::wstring& plain) {
    return GetFileAttributesW(ApiPath(plain).c_str());
}

std::wstring CanonicalPath(const std::wstring& plain, DWORD* error) {
    if (error != nullptr) {
        *error = ERROR_SUCCESS;
    }
    Handle dir(CreateFileW(ApiPath(plain).c_str(), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!dir.valid()) {
        if (error != nullptr) {
            *error = GetLastError();
        }
        return std::wstring();
    }
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length =
            GetFinalPathNameByHandleW(dir.get(), &buffer[0], static_cast<DWORD>(buffer.size()), VOLUME_NAME_DOS);
        if (length == 0) {
            if (error != nullptr) {
                *error = GetLastError();
            }
            return std::wstring();
        }
        if (length < buffer.size()) {
            buffer.resize(length);
            break;
        }
        buffer.resize(length + 1);
    }
    std::wstring result = StripLongPrefix(buffer);
    for (wchar_t& ch : result) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }
    while (result.size() > 3 && result.back() == L'\\') {
        result.pop_back();
    }
    return result;
}

bool PathsEqual(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) ==
           CSTR_EQUAL;
}

bool IsUnderOrEqual(const std::wstring& child, const std::wstring& parent) {
    if (parent.empty() || child.empty()) {
        return false;
    }
    if (PathsEqual(child, parent)) {
        return true;
    }
    std::wstring prefix = parent;
    if (prefix.back() != L'\\') {
        prefix.push_back(L'\\');
    }
    if (child.size() <= prefix.size()) {
        return false;
    }
    return CompareStringOrdinal(child.c_str(), static_cast<int>(prefix.size()), prefix.c_str(),
                                static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

std::wstring VolumeRootOf(const std::wstring& plain) {
    wchar_t root[MAX_PATH] = {0};
    if (!GetVolumePathNameW(ApiPath(plain).c_str(), root, MAX_PATH)) {
        return std::wstring();
    }
    return StripLongPrefix(std::wstring(root));
}

bool CheckVolumeSupported(const std::wstring& plain, std::wstring& error) {
    const std::wstring root = VolumeRootOf(plain);
    if (root.empty()) {
        error = L"Не удалось определить том для пути: " + plain;
        return false;
    }
    const UINT type = GetDriveTypeW(root.c_str());
    if (type == DRIVE_CDROM) {
        error = L"Оптические диски не поддерживаются: " + root;
        return false;
    }
    if (type == DRIVE_NO_ROOT_DIR || type == DRIVE_UNKNOWN) {
        error = L"Том недоступен: " + root;
        return false;
    }
    wchar_t file_system[64] = {0};
    if (!GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, file_system, 64)) {
        error = L"Не удалось прочитать сведения о томе " + root + L": " + Win32ErrorText(GetLastError());
        return false;
    }
    return true;
}

std::wstring DaclToSddl(PSECURITY_DESCRIPTOR descriptor) {
    if (descriptor == nullptr) {
        return std::wstring();
    }
    LPWSTR text = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                              &text, nullptr)) {
        return std::wstring();
    }
    std::wstring result(text != nullptr ? text : L"");
    if (text != nullptr) {
        LocalFree(text);
    }
    return result;
}

FsCapabilities ProbeFilesystem(const std::wstring& parent, std::wstring& error) {    FsCapabilities caps;
    error.clear();
    const std::wstring root = VolumeRootOf(parent);
    if (root.empty()) {
        error = L"Не удалось определить том: " + parent;
        return caps;
    }
    caps.remote = GetDriveTypeW(root.c_str()) == DRIVE_REMOTE;
    wchar_t file_system[64] = {0};
    if (GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, file_system, 64)) {
        caps.file_system = file_system;
    }
    const bool is_ntfs = _wcsicmp(caps.file_system.c_str(), L"NTFS") == 0;
    const bool is_refs = _wcsicmp(caps.file_system.c_str(), L"ReFS") == 0;
    const bool local_ntfs = is_ntfs && !caps.remote;
    caps.attribute_mask =
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE;
    if (is_ntfs) {
        caps.attribute_mask |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_TEMPORARY;
        caps.time_tolerance_ms = caps.remote ? 2000 : 0;
    } else if (_wcsicmp(caps.file_system.c_str(), L"exFAT") == 0) {
        caps.time_tolerance_ms = 2000;
    } else {
        caps.time_tolerance_ms = 2000;
    }
    if (local_ntfs) {
        caps.supports_acl = true;
        caps.supports_streams = true;
        caps.supports_reparse = true;
        caps.supports_hardlinks = true;
        caps.checks_creation_time = true;
        caps.supports_dir_streams = true;
        return caps;
    }

    const std::wstring file = JoinPath(parent, L".linkerino-probe-" + NewGuidString() + L".tmp");
    Handle probe(CreateFileW(ApiPath(file).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                             nullptr));
    if (!probe.valid()) {
        error = L"Нет доступа на запись в " + parent + L": " + Win32ErrorText(GetLastError());
        return caps;
    }
    probe.Close();

    {
        const std::wstring stream_path = file + L":probe:$DATA";
        Handle writer(CreateFileW(ApiPath(stream_path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
        if (writer.valid()) {
            const char payload[] = "probe";
            DWORD written = 0;
            const BOOL wrote = WriteFile(writer.get(), payload, 5, &written, nullptr);
            writer.Close();
            Handle reader(CreateFileW(ApiPath(stream_path).c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                      nullptr));
            if (reader.valid()) {
                char buffer[8] = {0};
                DWORD read = 0;
                caps.supports_streams =
                caps.supports_streams = wrote != FALSE &&
                                        ReadFile(reader.get(), buffer, 5, &read, nullptr) != FALSE && read == 5 &&
                                        memcmp(buffer, payload, 5) == 0;
        }
    }


    const bool acl_capable = caps.remote || is_refs;
    if (acl_capable) {
        PSECURITY_DESCRIPTOR original = nullptr;
        PACL original_acl = nullptr;
        if (GetNamedSecurityInfoW(ApiPath(file).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                  &original_acl, nullptr, &original) == ERROR_SUCCESS) {
            SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
            PSID everyone = nullptr;
            if (AllocateAndInitializeSid(&world_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone)) {
                const DWORD sid_length = GetLengthSid(everyone);
                std::vector<BYTE> storage(sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) + sid_length + 32);
                PACL probe_acl = reinterpret_cast<PACL>(storage.data());
                if (InitializeAcl(probe_acl, static_cast<DWORD>(storage.size()), ACL_REVISION) &&
                    AddAccessDeniedAce(probe_acl, ACL_REVISION, FILE_WRITE_DATA, everyone)) {
                    std::wstring api_path = ApiPath(file);
                    if (SetNamedSecurityInfoW(&api_path[0], SE_FILE_OBJECT,
                                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                              nullptr, probe_acl, nullptr) == ERROR_SUCCESS) {
                        PSECURITY_DESCRIPTOR after = nullptr;
                        PACL acl_after = nullptr;
                        bool protected_dacl = false;
                        if (GetNamedSecurityInfoW(ApiPath(file).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                                  nullptr, nullptr, &acl_after, nullptr, &after) == ERROR_SUCCESS) {
                            SECURITY_DESCRIPTOR_CONTROL control = 0;
                            DWORD revision = 0;
                            if (GetSecurityDescriptorControl(after, &control, &revision)) {
                                protected_dacl = (control & SE_DACL_PROTECTED) != 0;
                            }
                            LocalFree(after);
                        }
                        Handle deny_check(CreateFileW(ApiPath(file).c_str(), GENERIC_WRITE,
                                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
                        const bool write_blocked = !deny_check.valid();
                        deny_check.Close();
                        caps.supports_acl = protected_dacl && write_blocked;
                        LogLine(L"acl probe " + parent + L": protected=" + std::to_wstring(protected_dacl) +
                                L" deny-enforced=" + std::to_wstring(write_blocked));
                        SetNamedSecurityInfoW(&api_path[0], SE_FILE_OBJECT,
                                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                              nullptr, original_acl, nullptr);
                    }
                }
                FreeSid(everyone);
            }
            LocalFree(original);
        }
    }
    {
        FILETIME target = {};
        SYSTEMTIME system_time = {};
        system_time.wYear = 2000;
        system_time.wMonth = 1;
        system_time.wDay = 1;
        SystemTimeToFileTime(&system_time, &target);
        Handle handle(CreateFileW(ApiPath(file).c_str(), FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (handle.valid() && SetFileTime(handle.get(), &target, nullptr, nullptr)) {
            BY_HANDLE_FILE_INFORMATION info = {};
            if (GetFileInformationByHandle(handle.get(), &info)) {
                const LONGLONG difference = static_cast<LONGLONG>(FileTimeToU64(info.ftCreationTime)) -
                                            static_cast<LONGLONG>(FileTimeToU64(target));
                const LONGLONG absolute = difference < 0 ? -difference : difference;
                caps.checks_creation_time = absolute <= 2000LL * 10000LL;
            }
        }
    }

    {
        const std::wstring probe_dir = JoinPath(parent, L".linkerino-dirprobe-" + NewGuidString());
        if (CreateDirectoryW(ApiPath(probe_dir).c_str(), nullptr)) {
            const std::wstring dir_stream_path = probe_dir + L":probe:$DATA";
            const char dir_payload[] = "dirprobe";
            Handle dir_writer(CreateFileW(ApiPath(dir_stream_path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL, nullptr));
            if (dir_writer.valid()) {
                DWORD written = 0;
                const BOOL wrote = WriteFile(dir_writer.get(), dir_payload, 8, &written, nullptr);
                dir_writer.Close();
                Handle dir_reader(CreateFileW(ApiPath(dir_stream_path).c_str(), GENERIC_READ,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, nullptr));
                if (dir_reader.valid()) {
                    char buffer[16] = {0};
                    DWORD read = 0;
                    caps.supports_dir_streams = wrote != FALSE &&
                                                ReadFile(dir_reader.get(), buffer, 8, &read, nullptr) != FALSE &&
                                                read == 8 && memcmp(buffer, dir_payload, 8) == 0;
                }
            }
            RemoveDirectoryW(ApiPath(probe_dir).c_str());
        }
        }
    }

    {
        const std::wstring second = file + L".link";
        caps.supports_hardlinks = CreateHardLinkW(ApiPath(second).c_str(), ApiPath(file).c_str(), nullptr) != FALSE;
        if (caps.supports_hardlinks) {
            DeleteFileW(ApiPath(second).c_str());
        }
    }
    DeleteFileW(ApiPath(file).c_str());

    LogLine(L"fs probe " + parent + L" fs=" + caps.file_system + L" remote=" + std::to_wstring(caps.remote) +
            L" acl=" + std::to_wstring(caps.supports_acl) + L" streams=" + std::to_wstring(caps.supports_streams) +
            L" dir_streams=" + std::to_wstring(caps.supports_dir_streams) + L" links=" +
            std::to_wstring(caps.supports_hardlinks) + L" creation=" + std::to_wstring(caps.checks_creation_time));

    if (caps.remote) {
        const std::wstring link = JoinPath(parent, L".linkerino-linkprobe-" + NewGuidString());
        std::wstring link_error;
        caps.supports_reparse = CreateSymlinkRaw(link, parent, true, link_error);
        if (caps.supports_reparse) {
            RemoveDirectoryW(ApiPath(link).c_str());
            DeleteFileW(ApiPath(link).c_str());
        }
    }
    return caps;
}

std::wstring NewGuidString() {
    GUID guid = {};
    if (FAILED(CoCreateGuid(&guid))) {
        SYSTEMTIME now = {};
        GetSystemTime(&now);
        wchar_t fallback[64] = {0};
        swprintf_s(fallback, L"%04u%02u%02u%02u%02u%02u%03u", now.wYear, now.wMonth, now.wDay, now.wHour,
                   now.wMinute, now.wSecond, now.wMilliseconds);
        return fallback;
    }
    wchar_t buffer[64] = {0};
    if (StringFromGUID2(guid, buffer, 64) == 0) {
        return L"guid";
    }
    std::wstring text(buffer);
    if (!text.empty() && text.front() == L'{') {
        text.erase(0, 1);
    }
    if (!text.empty() && text.back() == L'}') {
        text.pop_back();
    }
    return text;
}

std::uint64_t FileTimeToU64(const FILETIME& value) {
    ULARGE_INTEGER number = {};
    number.LowPart = value.dwLowDateTime;
    number.HighPart = value.dwHighDateTime;
    return number.QuadPart;
}

std::wstring ExeDirectory() {
    const std::wstring exe = ExePath();
    return exe.empty() ? std::wstring() : ParentPath(exe);
}

void LogLine(const std::wstring& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (!g_log_ready) {
        InitLogLocked();
    }
    if (g_log_path.empty()) {
        return;
    }
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    wchar_t stamp[64] = {0};
    swprintf_s(stamp, L"%04u-%02u-%02u %02u:%02u:%02u ", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
               now.wSecond);
    AppendUtf8(g_log_path, std::wstring(stamp) + line + L"\r\n");
}

std::wstring JournalDirectory() {
    static std::wstring cached;
    static std::once_flag once;
    std::call_once(once, []() {
        std::wstring dir;
        PWSTR local = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local)) && local != nullptr) {
            dir = JoinPath(local, L"Linkerino");
            CoTaskMemFree(local);
        } else {
            const std::wstring exe_dir = ExeDirectory();
            dir = exe_dir.empty() ? std::wstring() : JoinPath(exe_dir, L"Linkerino-data");
        }
        if (!dir.empty()) {
            SHCreateDirectoryExW(nullptr, ApiPath(dir).c_str(), nullptr);
        }
        cached = dir;
    });
    return cached;
}

DWORD WindowsBuildNumber() {
    static DWORD build = 0;
    if (build == 0) {
        struct OsVersionInfo {
            ULONG size;
            ULONG major;
            ULONG minor;
            ULONG build;
            ULONG platform;
            wchar_t service_pack[128];
        } info = {};
        info.size = sizeof(info);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != nullptr) {
            using RtlGetVersionFn = LONG(WINAPI*)(OsVersionInfo*);
            const auto fn = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
            if (fn != nullptr && fn(&info) == 0) {
                build = info.build == 0 ? 7601 : info.build;
            }
        }
        if (build == 0) {
            build = 7601;
        }
    }
    return build;
}

bool CreateSymlinkRaw(const std::wstring& link, const std::wstring& target, bool directory, std::wstring& error,
                      DWORD* error_code) {
    DWORD flags = directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
    const bool is_absolute = (target.size() >= 2 && target[1] == L':') ||
                             (target.size() >= 2 && target[0] == L'\\' && target[1] == L'\\');
    const std::wstring stored_target = (is_absolute && target.size() >= MAX_PATH) ? ApiPath(target) : target;
    const bool try_unprivileged = WindowsBuildNumber() >= 15063;
    BOOL ok = FALSE;
    if (try_unprivileged) {
        ok = CreateSymbolicLinkW(ApiPath(link).c_str(), stored_target.c_str(), flags | 0x2);
        if (!ok) {
            const DWORD first_error = GetLastError();
            if (first_error != ERROR_PRIVILEGE_NOT_HELD) {
                error = Win32ErrorText(first_error);
                if (error_code != nullptr) {
                    *error_code = first_error;
                }
                return false;
            }
        }
    }
    if (!ok) {
        ok = CreateSymbolicLinkW(ApiPath(link).c_str(), stored_target.c_str(), flags);
        if (!ok) {
            const DWORD code = GetLastError();
            error = Win32ErrorText(code);
            if (error_code != nullptr) {
                *error_code = code;
            }
            return false;
        }
    }
    if (error_code != nullptr) {
        *error_code = ERROR_SUCCESS;
    }
    return true;
}

bool CreateSymlinkCompat(const std::wstring& link, const std::wstring& target, std::wstring& error,
                         DWORD* error_code) {
    if (CreateSymlinkRaw(link, target, true, error, error_code)) {
        return true;
    }
    if (error_code != nullptr && *error_code == ERROR_PRIVILEGE_NOT_HELD) {
        error += L" Нужны права администратора или включённый режим разработчика.";
    }
    return false;
}

std::string ToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return std::string();
    }
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length, nullptr, nullptr);
    return result;
}

std::wstring FromUtf8(const std::string& text) {
    if (text.empty()) {
        return std::wstring();
    }
    const int length =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        return std::wstring();
    }
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), &result[0], length);
    return result;
}

}  // namespace linkerino
