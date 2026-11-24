#include "engine.h"

#include "win_util.h"

#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shellapi.h>
#include <winioctl.h>

#include <algorithm>
#include <cstdio>
#include <vector>

namespace linkerino {
namespace {

constexpr DWORD kBufferSize = 1u << 20;
constexpr DWORD kFileAttributeRecallOnOpen = 0x00040000;
constexpr DWORD kFileAttributeRecallOnDataAccess = 0x00400000;
constexpr DWORD kMaxDepth = 512;
constexpr DWORD kMaxStreamPath = MAX_PATH - 32;

#pragma pack(push, 1)
struct ReparseDataBufferLocal {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    };
};
#pragma pack(pop)

struct EntryStream {
    std::wstring name;
    std::uint64_t size = 0;
    std::wstring hash;
};

// Find handles must be released with FindClose, not CloseHandle: a leaked
// handle keeps the directory (or file) busy and blocks renaming it.
class FindHandle {
public:
    FindHandle() = default;
    explicit FindHandle(HANDLE value) : handle_(value) {}
    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;
    ~FindHandle() { Close(); }

    void Close() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            FindClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

struct Entry {
    std::wstring rel;
    bool is_dir = false;
    DWORD attrs = 0;
    DWORD links = 1;
    std::uint64_t size = 0;
    FILETIME created = {};
    FILETIME modified = {};
    FILETIME accessed = {};
    std::uint64_t volume_serial = 0;
    std::uint64_t file_index = 0;
    std::wstring dacl;
    std::vector<EntryStream> streams;
    std::wstring hash;

    std::uint64_t WorkBytes() const {
        std::uint64_t total = size;
        for (const EntryStream& stream : streams) {
            total += stream.size;
        }
        return total;
    }
};

class Sha256 {
public:
    Sha256() {
        if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
            return;
        }
        DWORD object_length = 0;
        DWORD written = 0;
        if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
                              sizeof(object_length), &written, 0) < 0) {
            Close();
            return;
        }
        DWORD hash_length = 0;
        if (BCryptGetProperty(algorithm_, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length),
                              &written, 0) < 0) {
            Close();
            return;
        }
        object_.resize(object_length);
        digest_.resize(hash_length);
        if (BCryptCreateHash(algorithm_, &hash_, object_.data(), object_length, nullptr, 0, 0) < 0) {
            Close();
        }
    }

    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    ~Sha256() { Close(); }

    bool ok() const { return hash_ != nullptr; }

    bool Update(const void* data, DWORD length) {
        return hash_ != nullptr && BCryptHashData(hash_, static_cast<PUCHAR>(const_cast<void*>(data)), length, 0) >= 0;
    }

    std::wstring FinishHex() {
        if (hash_ == nullptr) {
            return std::wstring();
        }
        if (BCryptFinishHash(hash_, digest_.data(), static_cast<ULONG>(digest_.size()), 0) < 0) {
            return std::wstring();
        }
        static const wchar_t* digits = L"0123456789abcdef";
        std::wstring text;
        text.reserve(digest_.size() * 2);
        for (BYTE byte : digest_) {
            text.push_back(digits[byte >> 4]);
            text.push_back(digits[byte & 0x0F]);
        }
        return text;
    }

private:
    void Close() {
        if (hash_ != nullptr) {
            BCryptDestroyHash(hash_);
            hash_ = nullptr;
        }
        if (algorithm_ != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
            algorithm_ = nullptr;
        }
    }

    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<BYTE> object_;
    std::vector<BYTE> digest_;
};

bool Fail(std::wstring& error, const std::wstring& text) {
    error = text;
    return false;
}

std::wstring StreamSuffix(const std::wstring& name) {
    return L":" + name + L":$DATA";
}

std::wstring SidText(PSID sid) {
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text) || text == nullptr) {
        return L"?";
    }
    std::wstring result(text);
    LocalFree(text);
    return result;
}

std::wstring AclSignature(PACL acl) {
    if (acl == nullptr) {
        return L"<null>";
    }
    ACL_SIZE_INFORMATION info = {};
    if (!GetAclInformation(acl, &info, sizeof(info), AclSizeInformation)) {
        return L"<unreadable>";
    }
    std::wstring signature;
    for (DWORD index = 0; index < info.AceCount; ++index) {
        LPVOID ace = nullptr;
        if (!GetAce(acl, index, &ace)) {
            return L"<unreadable-ace>";
        }
        const ACE_HEADER* header = static_cast<const ACE_HEADER*>(ace);
        const DWORD effective_flags = header->AceFlags & ~static_cast<DWORD>(INHERITED_ACE);
        wchar_t part[96] = {0};
        swprintf_s(part, L"%u|%lu|", static_cast<unsigned>(header->AceType),
                   static_cast<unsigned long>(effective_flags));
        signature += part;
        switch (header->AceType) {
            case ACCESS_ALLOWED_ACE_TYPE: {
                const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
                swprintf_s(part, L"%lu|", static_cast<unsigned long>(allowed->Mask));
                signature += part;
                signature += SidText(const_cast<PSID>(static_cast<const void*>(&allowed->SidStart)));
                break;
            }
            case ACCESS_DENIED_ACE_TYPE: {
                const auto* denied = static_cast<const ACCESS_DENIED_ACE*>(ace);
                swprintf_s(part, L"%lu|", static_cast<unsigned long>(denied->Mask));
                signature += part;
                signature += SidText(const_cast<PSID>(static_cast<const void*>(&denied->SidStart)));
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
                const auto* object = static_cast<const ACCESS_ALLOWED_OBJECT_ACE*>(ace);
                swprintf_s(part, L"%lu|%lu|", static_cast<unsigned long>(object->Mask),
                           static_cast<unsigned long>(object->Flags));
                signature += part;
                if ((object->Flags & ACE_OBJECT_TYPE_PRESENT) != 0) {
                    signature += L"object=";
                    signature += SidText(const_cast<PSID>(static_cast<const void*>(&object->ObjectType)));
                }
                signature += SidText(const_cast<PSID>(static_cast<const void*>(&object->SidStart)));
                break;
            }
            default:
                signature += L"opaque";
                break;
        }
        signature += L";";
    }
    return signature;
}

bool ReadDaclSignature(const std::wstring& plain, std::wstring& signature, std::wstring& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL acl = nullptr;
    const DWORD result = GetNamedSecurityInfoW(ApiPath(plain).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                               nullptr, nullptr, &acl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        return Fail(error, L"Не удалось прочитать права доступа к " + plain + L": " + Win32ErrorText(result));
    }
    signature = AclSignature(acl);
    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    return true;
}

// Copies the source DACL as an explicit (protected) ACL: the copy must not
// inherit extra rights from the destination parent, and the comparison must
// not depend on which ACEs happen to be marked as inherited on either volume.
class ExplicitAcl {
public:
    explicit ExplicitAcl(PACL source) {
        if (source == nullptr) {
            return;
        }
        ACL_SIZE_INFORMATION info = {};
        if (!GetAclInformation(source, &info, sizeof(info), AclSizeInformation)) {
            return;
        }
        bytes_.resize(static_cast<std::size_t>(info.AclBytesInUse) * 2 + sizeof(ACL) + 64);
        acl_ = reinterpret_cast<PACL>(bytes_.data());
        if (!InitializeAcl(acl_, static_cast<DWORD>(bytes_.size()), ACL_REVISION)) {
            acl_ = nullptr;
            return;
        }
        for (DWORD index = 0; index < info.AceCount; ++index) {
            LPVOID ace = nullptr;
            if (!GetAce(source, index, &ace)) {
                acl_ = nullptr;
                return;
            }
            const auto* header = static_cast<const ACE_HEADER*>(ace);
            std::vector<BYTE> copy(header->AceSize);
            memcpy(copy.data(), ace, header->AceSize);
            auto* copy_header = reinterpret_cast<ACE_HEADER*>(copy.data());
            copy_header->AceFlags = static_cast<BYTE>(copy_header->AceFlags & ~INHERITED_ACE);
            if (!AddAce(acl_, ACL_REVISION, MAXDWORD, copy_header, header->AceSize)) {
                acl_ = nullptr;
                return;
            }
        }
    }

    ExplicitAcl(const ExplicitAcl&) = delete;
    ExplicitAcl& operator=(const ExplicitAcl&) = delete;

    PACL get() const { return acl_; }

private:
    std::vector<BYTE> bytes_;
    PACL acl_ = nullptr;
};

bool ApplyDacl(const std::wstring& source, const std::wstring& dest, std::wstring& error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL acl = nullptr;
    DWORD result = GetNamedSecurityInfoW(ApiPath(source).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                         nullptr, &acl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        return Fail(error, L"Не удалось прочитать права доступа к " + source + L": " + Win32ErrorText(result));
    }
    ExplicitAcl explicit_acl(acl);
    if (acl != nullptr && explicit_acl.get() == nullptr) {
        if (descriptor != nullptr) {
            LocalFree(descriptor);
        }
        return Fail(error, L"Не удалось подготовить права доступа для " + dest);
    }
    std::wstring dest_api = ApiPath(dest);
    result = SetNamedSecurityInfoW(&dest_api[0], SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                   explicit_acl.get(), nullptr);
    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    if (result != ERROR_SUCCESS) {
        return Fail(error, L"Не удалось сохранить права доступа для " + dest + L": " + Win32ErrorText(result));
    }
    return true;
}

bool ReadMeta(const std::wstring& plain, Entry& entry, std::wstring& error) {
    Handle file(CreateFileW(ApiPath(plain).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!file.valid()) {
        return Fail(error, L"Не удалось открыть " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(file.get(), &info)) {
        return Fail(error, L"Не удалось прочитать сведения о " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    entry.attrs = info.dwFileAttributes;
    entry.links = info.nNumberOfLinks;
    entry.created = info.ftCreationTime;
    entry.modified = info.ftLastWriteTime;
    entry.accessed = info.ftLastAccessTime;
    entry.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    entry.volume_serial = info.dwVolumeSerialNumber;
    entry.file_index = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    entry.is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    return true;
}

bool UnsupportedReason(const Entry& entry, const std::wstring& plain, std::wstring& reason) {
    if ((entry.attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        reason = L"точка повторной обработки (ссылка, junction или другая): " + plain;
        return true;
    }
    if ((entry.attrs & FILE_ATTRIBUTE_ENCRYPTED) != 0) {
        reason = L"зашифрованный файл EFS: " + plain;
        return true;
    }
    if ((entry.attrs & FILE_ATTRIBUTE_OFFLINE) != 0) {
        reason = L"файл недоступен офлайн: " + plain;
        return true;
    }
    if ((entry.attrs & (kFileAttributeRecallOnOpen | kFileAttributeRecallOnDataAccess)) != 0) {
        reason = L"облачная заглушка, содержимое которой ещё не скачано: " + plain;
        return true;
    }
    if (!entry.is_dir && entry.links > 1) {
        reason = L"файл имеет несколько жёстких ссылок: " + plain;
        return true;
    }
    return false;
}

bool EnumNamedStreams(const std::wstring& plain, bool is_dir, std::vector<EntryStream>& out, std::wstring& error) {
    if (plain.size() >= kMaxStreamPath) {
        return Fail(error, L"Слишком длинный путь для безопасного переноса (больше " + std::to_wstring(kMaxStreamPath) + L" символов): " + plain);
    }
    WIN32_FIND_STREAM_DATA data = {};
    FindHandle find(FindFirstStreamW(plain.c_str(), FindStreamInfoStandard, &data, 0));
    if (!find.valid()) {
        const DWORD code = GetLastError();
        if (code == ERROR_HANDLE_EOF || code == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return Fail(error, L"Не удалось перечислить потоки файла " + plain + L": " + Win32ErrorText(code));
    }
    do {
        const std::wstring name = data.cStreamName;
        if (name == L"::$DATA") {
            continue;
        }
        if (is_dir) {
            return Fail(error, L"Именованный поток на каталоге не поддерживается: " + plain + name);
        }
        std::wstring clean = name;
        if (!clean.empty() && clean.front() == L':') {
            clean.erase(0, 1);
        }
        const std::wstring tail = L":$DATA";
        if (clean.size() > tail.size() && clean.compare(clean.size() - tail.size(), tail.size(), tail) == 0) {
            clean.erase(clean.size() - tail.size());
        }
        EntryStream stream;
        stream.name = clean;
        stream.size = static_cast<std::uint64_t>(data.StreamSize.QuadPart);
        out.push_back(stream);
    } while (FindNextStreamW(find.get(), &data));
    const DWORD last = GetLastError();
    if (last != ERROR_NO_MORE_FILES && last != ERROR_HANDLE_EOF) {
        return Fail(error, L"Ошибка перечисления потоков " + plain + L": " + Win32ErrorText(last));
    }
    return true;
}

bool ScanDir(const std::wstring& root, const std::wstring& rel, DWORD depth, std::vector<Entry>& entries,
             std::wstring& error) {
    if (depth > kMaxDepth) {
        return Fail(error, L"Слишком глубокая вложенность каталогов: " + rel);
    }
    const std::wstring plain = rel.empty() ? root : JoinPath(root, rel);
    Entry directory;
    if (!ReadMeta(plain, directory, error)) {
        return false;
    }
    std::wstring reason;
    if (UnsupportedReason(directory, plain, reason)) {
        return Fail(error, reason);
    }
    directory.rel = rel;
    directory.is_dir = true;
    if (!ReadDaclSignature(plain, directory.dacl, error)) {
        return false;
    }
    if (!EnumNamedStreams(plain, true, directory.streams, error)) {
        return false;
    }
    entries.push_back(directory);

    WIN32_FIND_DATAW find_data = {};
    FindHandle find(FindFirstFileExW(ApiPath(JoinPath(plain, L"*")).c_str(), FindExInfoBasic, &find_data,
                                 FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH));
    if (!find.valid()) {
        const DWORD code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return Fail(error, L"Не удалось прочитать содержимое " + plain + L": " + Win32ErrorText(code));
    }
    bool keep_going = true;
    do {
        const std::wstring name = find_data.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }
        const std::wstring child_rel = rel.empty() ? name : JoinPath(rel, name);
        const std::wstring child_plain = JoinPath(plain, name);
        const bool is_dir = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            error = L"Ссылка или junction внутри папки не поддерживается: " + child_plain;
            keep_going = false;
            break;
        }
        if (is_dir) {
            if (!ScanDir(root, child_rel, depth + 1, entries, error)) {
                keep_going = false;
                break;
            }
        } else {
            Entry file;
            if (!ReadMeta(child_plain, file, error)) {
                keep_going = false;
                break;
            }
            if (UnsupportedReason(file, child_plain, reason)) {
                error = reason;
                keep_going = false;
                break;
            }
            file.rel = child_rel;
            if (!ReadDaclSignature(child_plain, file.dacl, error)) {
                keep_going = false;
                break;
            }
            if (!EnumNamedStreams(child_plain, false, file.streams, error)) {
                keep_going = false;
                break;
            }
            entries.push_back(file);
        }
    } while (FindNextFileW(find.get(), &find_data));
    if (!keep_going) {
        return false;
    }
    const DWORD last = GetLastError();
    if (last != ERROR_NO_MORE_FILES) {
        return Fail(error, L"Ошибка чтения содержимого " + plain + L": " + Win32ErrorText(last));
    }
    return true;
}

struct CopyContext {
    ProgressSink* sink = nullptr;
    Phase phase = Phase::Copy;
    std::uint64_t bytes_done = 0;
    std::uint64_t bytes_total = 0;
    std::uint64_t files_done = 0;
    std::uint64_t files_total = 0;
    std::wstring current;
    bool cancelled = false;
    std::uint64_t last_report = 0;

    void Report(bool force = false) {
        if (sink == nullptr) {
            return;
        }
        const std::uint64_t now = GetTickCount64();
        if (!force && now - last_report < 100) {
            return;
        }
        last_report = now;
        Progress progress;
        progress.phase = phase;
        progress.bytes_done = bytes_done;
        progress.bytes_total = bytes_total;
        progress.files_done = files_done;
        progress.files_total = files_total;
        progress.item = current;
        sink->OnProgress(progress);
    }

    bool CancelRequested() { return sink != nullptr && sink->CancelRequested(); }
};

bool CopyStream(const std::wstring& source, const std::wstring& dest, CopyContext& context, std::wstring& hash,
                std::wstring& error) {
    Handle input(CreateFileW(ApiPath(source).c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!input.valid()) {
        return Fail(error, L"Не удалось открыть для чтения " + source + L": " + Win32ErrorText(GetLastError()));
    }
    Handle output(CreateFileW(ApiPath(dest).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                              nullptr));
    if (!output.valid()) {
        return Fail(error, L"Не удалось создать файл " + dest + L": " + Win32ErrorText(GetLastError()));
    }
    Sha256 hasher;
    if (!hasher.ok()) {
        return Fail(error, L"Не удалось запустить SHA-256 для " + source);
    }
    std::vector<BYTE> buffer(kBufferSize);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(input.get(), buffer.data(), kBufferSize, &read, nullptr)) {
            return Fail(error, L"Ошибка чтения " + source + L": " + Win32ErrorText(GetLastError()));
        }
        if (read == 0) {
            break;
        }
        DWORD written = 0;
        if (!WriteFile(output.get(), buffer.data(), read, &written, nullptr) || written != read) {
            return Fail(error, L"Ошибка записи " + dest + L": " + Win32ErrorText(GetLastError()));
        }
        if (!hasher.Update(buffer.data(), read)) {
            return Fail(error, L"Ошибка вычисления SHA-256 для " + source);
        }
        context.bytes_done += read;
        context.Report();
        if (context.CancelRequested()) {
            context.cancelled = true;
            return Fail(error, L"Отменено пользователем");
        }
    }
    if (!FlushFileBuffers(output.get())) {
        return Fail(error, L"Не удалось сбросить данные на диск для " + dest + L": " + Win32ErrorText(GetLastError()));
    }
    hash = hasher.FinishHex();
    if (hash.empty()) {
        return Fail(error, L"Не удалось вычислить SHA-256 для " + dest);
    }
    return true;
}

bool SetTimesAndAttrs(const std::wstring& plain, const Entry& entry, bool is_dir, std::wstring& error) {
    Handle file(CreateFileW(ApiPath(plain).c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!file.valid()) {
        return Fail(error, L"Не удалось открыть для настройки " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    if (!SetFileTime(file.get(), &entry.created, &entry.accessed, &entry.modified)) {
        return Fail(error, L"Не удалось сохранить даты " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    file.Close();
    DWORD attrs = entry.attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY |
                                 FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
                                 FILE_ATTRIBUTE_TEMPORARY);
    if (is_dir) {
        attrs &= ~FILE_ATTRIBUTE_READONLY;
    }
    if (!SetFileAttributesW(ApiPath(plain).c_str(), attrs)) {
        return Fail(error, L"Не удалось сохранить атрибуты " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    return true;
}

bool CopyFileEntry(const std::wstring& source, const std::wstring& dest, Entry& entry, CopyContext& context,
                   std::wstring& error) {
    if (!CopyStream(source, dest, context, entry.hash, error)) {
        return false;
    }
    for (EntryStream& stream : entry.streams) {
        const std::wstring suffix = StreamSuffix(stream.name);
        if (!CopyStream(source + suffix, dest + suffix, context, stream.hash, error)) {
            return false;
        }
    }
    if (!ApplyDacl(source, dest, error)) {
        return false;
    }
    return SetTimesAndAttrs(dest, entry, false, error);
}

bool CopyTree(const Plan& plan, std::vector<Entry>& entries, CopyContext& context, const Faults& faults,
              std::wstring& error) {
    for (Entry& entry : entries) {
        if (!entry.is_dir) {
            continue;
        }
        const std::wstring dest = entry.rel.empty() ? plan.staging : JoinPath(plan.staging, entry.rel);
        if (!CreateDirectoryW(ApiPath(dest).c_str(), nullptr)) {
            const DWORD code = GetLastError();
            if (code != ERROR_ALREADY_EXISTS) {
                return Fail(error, L"Не удалось создать каталог " + dest + L": " + Win32ErrorText(code));
            }
        }
        const std::wstring source = entry.rel.empty() ? plan.source : JoinPath(plan.source, entry.rel);
        if (!ApplyDacl(source, dest, error)) {
            return false;
        }
    }
    for (Entry& entry : entries) {
        if (entry.is_dir) {
            continue;
        }
        if (faults.copy_failure) {
            return Fail(error, L"Тестовый сбой копирования");
        }
        const std::wstring source = JoinPath(plan.source, entry.rel);
        const std::wstring dest = JoinPath(plan.staging, entry.rel);
        context.current = entry.rel;
        context.Report(true);
        if (!CopyFileEntry(source, dest, entry, context, error)) {
            return false;
        }
        ++context.files_done;
        context.Report(true);
    }
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        if (!it->is_dir) {
            continue;
        }
        const std::wstring dest = it->rel.empty() ? plan.staging : JoinPath(plan.staging, it->rel);
        if (!SetTimesAndAttrs(dest, *it, true, error)) {
            return false;
        }
    }
    return true;
}

bool HashFile(const std::wstring& plain, std::wstring& hash, std::wstring& error) {
    Handle input(CreateFileW(ApiPath(plain).c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!input.valid()) {
        return Fail(error, L"Не удалось открыть для сверки " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    Sha256 hasher;
    if (!hasher.ok()) {
        return Fail(error, L"Не удалось запустить SHA-256");
    }
    std::vector<BYTE> buffer(kBufferSize);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(input.get(), buffer.data(), kBufferSize, &read, nullptr)) {
            return Fail(error, L"Ошибка чтения " + plain + L": " + Win32ErrorText(GetLastError()));
        }
        if (read == 0) {
            break;
        }
        if (!hasher.Update(buffer.data(), read)) {
            return Fail(error, L"Ошибка SHA-256 для " + plain);
        }
    }
    hash = hasher.FinishHex();
    return !hash.empty();
}

bool VerifyEntry(const std::wstring& root, const Entry& entry, CopyContext& context, std::wstring& error) {
    const std::wstring plain = entry.rel.empty() ? root : JoinPath(root, entry.rel);
    Entry actual;
    if (!ReadMeta(plain, actual, error)) {
        return false;
    }
    if (actual.is_dir != entry.is_dir) {
        return Fail(error, L"Тип объекта не совпадает: " + plain);
    }
    std::wstring signature;
    if (!ReadDaclSignature(plain, signature, error)) {
        return false;
    }
    if (signature != entry.dacl) {
        return Fail(error, L"Права доступа не совпадают: " + plain);
    }
    if (!entry.is_dir) {
        const DWORD attribute_mask = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY |
                                     FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
                                     FILE_ATTRIBUTE_TEMPORARY;
        if ((actual.attrs & attribute_mask) != (entry.attrs & attribute_mask)) {
            return Fail(error, L"Атрибуты файла не совпадают: " + plain);
        }
        if (actual.size != entry.size) {
            return Fail(error, L"Размер файла не совпадает: " + plain);
        }
        if (FileTimeToU64(actual.modified) != FileTimeToU64(entry.modified) ||
            FileTimeToU64(actual.created) != FileTimeToU64(entry.created)) {
            return Fail(error, L"Даты файла не совпадают: " + plain);
        }
        std::wstring hash;
        if (!HashFile(plain, hash, error)) {
            return false;
        }
        if (hash != entry.hash) {
            return Fail(error, L"Содержимое файла не совпадает: " + plain);
        }
        context.bytes_done += entry.size;
        context.Report();
        std::vector<EntryStream> streams;
        if (!EnumNamedStreams(plain, false, streams, error)) {
            return false;
        }
        if (streams.size() != entry.streams.size()) {
            return Fail(error, L"Набор потоков файла не совпадает: " + plain);
        }
        for (std::size_t index = 0; index < streams.size(); ++index) {
            const std::wstring suffix = StreamSuffix(entry.streams[index].name);
            std::wstring stream_hash;
            if (!HashFile(plain + suffix, stream_hash, error)) {
                return false;
            }
            if (stream_hash != entry.streams[index].hash) {
                return Fail(error, L"Содержимое потока не совпадает: " + plain + suffix);
            }
            context.bytes_done += entry.streams[index].size;
            context.Report();
        }
    } else {
        std::vector<EntryStream> streams;
        if (!EnumNamedStreams(plain, true, streams, error)) {
            return false;
        }
        if (!streams.empty()) {
            return Fail(error, L"На каталоге появился именованный поток: " + plain);
        }
        if (FileTimeToU64(actual.modified) != FileTimeToU64(entry.modified) ||
            FileTimeToU64(actual.created) != FileTimeToU64(entry.created)) {
            return Fail(error, L"Даты каталога не совпадают: " + plain);
        }
    }
    context.current = entry.rel;
    return true;
}

bool CollectRelativePaths(const std::wstring& root, const std::wstring& rel, std::vector<std::wstring>& out,
                          std::wstring& error, DWORD depth) {
    if (depth > kMaxDepth) {
        return Fail(error, L"Слишком глубокая вложенность при сверке: " + rel);
    }
    out.push_back(rel);
    const std::wstring plain = rel.empty() ? root : JoinPath(root, rel);
    WIN32_FIND_DATAW find_data = {};
    FindHandle find(FindFirstFileExW(ApiPath(JoinPath(plain, L"*")).c_str(), FindExInfoBasic, &find_data,
                                 FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH));
    if (!find.valid()) {
        const DWORD code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return Fail(error, L"Не удалось прочитать " + plain + L": " + Win32ErrorText(code));
    }
    do {
        const std::wstring name = find_data.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }
        const std::wstring child_rel = rel.empty() ? name : JoinPath(rel, name);
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if (!CollectRelativePaths(root, child_rel, out, error, depth + 1)) {
                return false;
            }
        } else {
            out.push_back(child_rel);
        }
    } while (FindNextFileW(find.get(), &find_data));
    const DWORD last = GetLastError();
    if (last != ERROR_NO_MORE_FILES) {
        return Fail(error, L"Ошибка чтения " + plain + L": " + Win32ErrorText(last));
    }
    return true;
}

bool VerifyTree(const std::wstring& root, const std::vector<Entry>& entries, CopyContext& context,
                std::wstring& error) {
    std::vector<std::wstring> actual_paths;
    if (!CollectRelativePaths(root, L"", actual_paths, error, 0)) {
        return false;
    }
    std::vector<std::wstring> expected_paths;
    expected_paths.reserve(entries.size());
    for (const Entry& entry : entries) {
        expected_paths.push_back(entry.rel);
    }
    if (actual_paths.size() != expected_paths.size()) {
        return Fail(error, L"Количество объектов в копии не совпадает с оригиналом");
    }
    const auto path_less = [](const std::wstring& left, const std::wstring& right) {
        return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(),
                                    static_cast<int>(right.size()), TRUE) == CSTR_LESS_THAN;
    };
    std::sort(actual_paths.begin(), actual_paths.end(), path_less);
    std::sort(expected_paths.begin(), expected_paths.end(), path_less);
    for (std::size_t index = 0; index < expected_paths.size(); ++index) {
        if (!PathsEqual(expected_paths[index], actual_paths[index])) {
            return Fail(error, L"Набор объектов в копии не совпадает: " + actual_paths[index]);
        }
    }
    for (const Entry& entry : entries) {
        context.current = entry.rel;
        context.Report();
        if (!VerifyEntry(root, entry, context, error)) {
            return false;
        }
        if (context.CancelRequested()) {
            context.cancelled = true;
            return Fail(error, L"Отменено пользователем");
        }
    }
    return true;
}

bool VerifySourceUnchanged(const Plan& plan, const std::vector<Entry>& entries, std::wstring& error) {
    for (const Entry& entry : entries) {
        const std::wstring plain = entry.rel.empty() ? plan.source : JoinPath(plan.source, entry.rel);
        Entry actual;
        if (!ReadMeta(plain, actual, error)) {
            return false;
        }
        if (actual.is_dir != entry.is_dir || actual.size != entry.size || actual.volume_serial != entry.volume_serial ||
            actual.file_index != entry.file_index ||
            FileTimeToU64(actual.modified) != FileTimeToU64(entry.modified)) {
            return Fail(error, L"Исходный объект изменился во время переноса: " + plain);
        }
        if (!entry.is_dir) {
            std::wstring hash;
            if (!HashFile(plain, hash, error)) {
                return false;
            }
            if (hash != entry.hash) {
                return Fail(error, L"Содержимое исходного файла изменилось во время переноса: " + plain);
            }
            std::wstring signature;
            if (!ReadDaclSignature(plain, signature, error)) {
                return false;
            }
            if (signature != entry.dacl) {
                return Fail(error, L"Права доступа к исходному файлу изменились: " + plain);
            }
        }
    }
    return true;
}

bool RemoveTreeNoFollow(const std::wstring& plain, std::wstring& error) {
    const DWORD attrs = PathAttributes(plain);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        if (!RemoveDirectoryW(ApiPath(plain).c_str()) && !DeleteFileW(ApiPath(plain).c_str())) {
            return Fail(error, L"Не удалось удалить ссылку " + plain + L": " + Win32ErrorText(GetLastError()));
        }
        return true;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        WIN32_FIND_DATAW find_data = {};
        FindHandle find(FindFirstFileExW(ApiPath(JoinPath(plain, L"*")).c_str(), FindExInfoBasic, &find_data,
                                     FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH));
        if (find.valid()) {
            do {
                const std::wstring name = find_data.cFileName;
                if (name == L"." || name == L"..") {
                    continue;
                }
                if (!RemoveTreeNoFollow(JoinPath(plain, name), error)) {
                    return false;
                }
            } while (FindNextFileW(find.get(), &find_data));
        }
        if (!RemoveDirectoryW(ApiPath(plain).c_str())) {
            return Fail(error, L"Не удалось удалить каталог " + plain + L": " + Win32ErrorText(GetLastError()));
        }
        return true;
    }
    if ((attrs & FILE_ATTRIBUTE_READONLY) != 0) {
        SetFileAttributesW(ApiPath(plain).c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    }
    if (!DeleteFileW(ApiPath(plain).c_str())) {
        return Fail(error, L"Не удалось удалить файл " + plain + L": " + Win32ErrorText(GetLastError()));
    }
    return true;
}

bool VerifySymlink(const std::wstring& link, const std::wstring& expected_target, std::uint64_t volume_serial,
                   std::uint64_t file_index, std::wstring& error);

bool DeleteBackupTree(const std::wstring& backup, const std::vector<Entry>& entries, const std::wstring& link,
                      const std::wstring& target, std::uint64_t volume_serial, std::uint64_t file_index,
                      const Faults& faults, std::wstring& error, std::wstring& stopped_at, bool& link_lost) {
    unsigned processed = 0;
    int deleted_files = 0;
    link_lost = false;
    for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
        if (processed++ % 32 == 0) {
            std::wstring link_error;
            if (!VerifySymlink(link, target, volume_serial, file_index, link_error)) {
                stopped_at = backup;
                link_lost = true;
                return Fail(error, L"Ссылка на новое место перестала быть доступной, удаление остановлено: " +
                                       link_error);
            }
        }
        const std::wstring plain = it->rel.empty() ? backup : JoinPath(backup, it->rel);
        stopped_at = plain;
        const DWORD attrs = PathAttributes(plain);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            return Fail(error, L"Объект резерва исчез: " + plain);
        }
        if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return Fail(error, L"В резерве появилась ссылка, удаление остановлено: " + plain);
        }
        if (it->is_dir) {
            if (!RemoveDirectoryW(ApiPath(plain).c_str())) {
                return Fail(error, L"Не удалось удалить каталог резерва " + plain + L": " + Win32ErrorText(GetLastError()));
            }
            continue;
        }
        Entry actual;
        if (!ReadMeta(plain, actual, error)) {
            return false;
        }
        if (actual.volume_serial != it->volume_serial || actual.file_index != it->file_index ||
            actual.size != it->size || FileTimeToU64(actual.modified) != FileTimeToU64(it->modified)) {
            return Fail(error, L"Файл резерва изменился, удаление остановлено: " + plain);
        }
        std::wstring hash;
        if (!HashFile(plain, hash, error)) {
            return false;
        }
        if (hash != it->hash) {
            return Fail(error, L"Содержимое файла резерва изменилось, удаление остановлено: " + plain);
        }
        for (const EntryStream& stream : it->streams) {
            std::wstring stream_hash;
            if (!HashFile(plain + StreamSuffix(stream.name), stream_hash, error)) {
                return false;
            }
            if (stream_hash != stream.hash) {
                return Fail(error, L"Содержимое потока резерва изменилось: " + plain);
            }
        }
        if ((attrs & FILE_ATTRIBUTE_READONLY) != 0) {
            SetFileAttributesW(ApiPath(plain).c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
        }
        if (!DeleteFileW(ApiPath(plain).c_str())) {
            return Fail(error, L"Не удалось удалить файл резерва " + plain + L": " + Win32ErrorText(GetLastError()));
        }
        ++deleted_files;
        if (faults.break_link_after_files > 0 && deleted_files == faults.break_link_after_files) {
            RemoveDirectoryW(ApiPath(link).c_str());
        }
    }
    stopped_at.clear();
    return true;
}

bool ProbeSymlink(const std::wstring& parent, const std::wstring& target, std::wstring& error, DWORD* error_code) {
    const std::wstring probe = JoinPath(parent, L".linkerino-probe-" + NewGuidString());
    if (!CreateSymlinkCompat(probe, target, error, error_code)) {
        return false;
    }
    if (!RemoveDirectoryW(ApiPath(probe).c_str()) && !DeleteFileW(ApiPath(probe).c_str())) {
        error = L"Не удалось убрать пробную ссылку " + probe + L": " + Win32ErrorText(GetLastError());
        if (error_code != nullptr) {
            *error_code = GetLastError();
        }
        return false;
    }
    return true;
}

bool FlushVolume(const std::wstring& plain) {
    const std::wstring root = VolumeRootOf(plain);
    if (root.size() < 2) {
        return false;
    }
    const std::wstring device = L"\\\\.\\" + root.substr(0, 2);
    Handle volume(CreateFileW(device.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, 0, nullptr));
    if (!volume.valid()) {
        LogLine(L"volume flush skipped: " + Win32ErrorText(GetLastError()));
        return false;
    }
    if (!FlushFileBuffers(volume.get())) {
        LogLine(L"volume flush failed: " + Win32ErrorText(GetLastError()));
        return false;
    }
    LogLine(L"volume flushed: " + root);
    return true;
}

void AppendProbeByte(const std::wstring& plain) {
    Handle file(CreateFileW(ApiPath(plain).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return;
    }
    DWORD written = 0;
    const char byte = 'x';
    WriteFile(file.get(), &byte, 1, &written, nullptr);
}

bool ReadIdentity(const std::wstring& plain, std::uint64_t& volume_serial, std::uint64_t& file_index,
                  std::wstring& error) {
    Entry entry;
    if (!ReadMeta(plain, entry, error)) {
        return false;
    }
    volume_serial = entry.volume_serial;
    file_index = entry.file_index;
    return true;
}

bool VerifySymlink(const std::wstring& link, const std::wstring& expected_target, std::uint64_t volume_serial,
                   std::uint64_t file_index, std::wstring& error) {
    const DWORD attrs = PathAttributes(link);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return Fail(error, L"Ссылка не создана: " + link);
    }
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        return Fail(error, L"На старом месте не ссылка: " + link);
    }
    Handle link_handle(CreateFileW(ApiPath(link).c_str(), FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!link_handle.valid()) {
        return Fail(error, L"Не удалось открыть ссылку " + link + L": " + Win32ErrorText(GetLastError()));
    }
    std::vector<BYTE> buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD returned = 0;
    if (!DeviceIoControl(link_handle.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, buffer.data(),
                         static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        return Fail(error, L"Не удалось прочитать ссылку " + link + L": " + Win32ErrorText(GetLastError()));
    }
    const auto* header = reinterpret_cast<const ReparseDataBufferLocal*>(buffer.data());
    if (header->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        return Fail(error, L"Ссылка имеет неверный тип (не символьная): " + link);
    }
    const auto& symlink = header->SymbolicLinkReparseBuffer;
    const std::size_t base = offsetof(ReparseDataBufferLocal, SymbolicLinkReparseBuffer) +
                             offsetof(decltype(ReparseDataBufferLocal::SymbolicLinkReparseBuffer), PathBuffer);
    const std::size_t offset = base + symlink.SubstituteNameOffset;
    const std::size_t length = symlink.SubstituteNameLength / sizeof(WCHAR);
    if (length == 0 || offset + length * sizeof(WCHAR) > buffer.size()) {
        return Fail(error, L"Ссылка не содержит путь назначения: " + link);
    }
    std::wstring stored(reinterpret_cast<const WCHAR*>(buffer.data() + offset), length);
    std::wstring target = stored;
    if (target.compare(0, 4, L"\\??\\") == 0) {
        target.erase(0, 4);
    }
    if (!PathsEqual(target, expected_target)) {
        return Fail(error, L"Ссылка указывает не туда: " + stored);
    }
    Handle follow(CreateFileW(ApiPath(link).c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!follow.valid()) {
        return Fail(error, L"Ссылка не открывает новую папку: " + Win32ErrorText(GetLastError()));
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(follow.get(), &info)) {
        return Fail(error, L"Не удалось проверить папку по ссылке: " + Win32ErrorText(GetLastError()));
    }
    const std::uint64_t actual_index =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    if (info.dwVolumeSerialNumber != volume_serial || actual_index != file_index) {
        return Fail(error, L"Ссылка ведёт на другую папку, а не на проверенную копию");
    }
    return true;
}

std::wstring JournalPath(const std::wstring& id) {
    return JoinPath(JournalDirectory(), L"journal-" + id + L".txt");
}

bool RenameWithRetry(const std::wstring& from, const std::wstring& to, DWORD* last_error) {
    bool reported = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (MoveFileExW(ApiPath(from).c_str(), ApiPath(to).c_str(), 0)) {
            if (reported) {
                LogLine(L"rename succeeded after retries");
            }
            return true;
        }
        const DWORD code = GetLastError();
        if (last_error != nullptr) {
            *last_error = code;
        }
        if (!reported) {
            LogLine(L"rename attempt " + std::to_wstring(attempt + 1) + L" failed: " + Win32ErrorText(code));
            reported = true;
        }
        if (code != ERROR_ACCESS_DENIED && code != ERROR_SHARING_VIOLATION && code != ERROR_LOCK_VIOLATION) {
            return false;
        }
        Sleep(150);
    }
    return false;
}

void WriteJournal(const std::wstring& id, const Plan& plan, const std::wstring& state, const std::wstring& extra) {
    if (id.empty() || JournalDirectory().empty()) {
        return;
    }
    SYSTEMTIME now = {};
    GetLocalTime(&now);
    wchar_t stamp[64] = {0};
    swprintf_s(stamp, L"%04u-%02u-%02uT%02u:%02u:%02u", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute,
               now.wSecond);
    std::wstring text;
    text += L"state=" + state + L"\r\n";
    text += L"time=" + std::wstring(stamp) + L"\r\n";
    text += L"source=" + plan.source + L"\r\n";
    text += L"dest=" + plan.dest_final + L"\r\n";
    text += L"staging=" + plan.staging + L"\r\n";
    text += L"backup=" + plan.backup + L"\r\n";
    if (!extra.empty()) {
        text += extra + L"\r\n";
    }
    const std::wstring path = JournalPath(id);
    Handle file(CreateFileW(ApiPath(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (!file.valid()) {
        return;
    }
    const std::string utf8 = ToUtf8(text);
    DWORD written = 0;
    WriteFile(file.get(), utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    FlushFileBuffers(file.get());
}

void RemoveJournal(const std::wstring& id) {
    if (id.empty()) {
        return;
    }
    DeleteFileW(ApiPath(JournalPath(id)).c_str());
}

bool IsCriticalDirectory(const std::wstring& path) {
    const wchar_t* variables[] = {L"SystemRoot", L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432",
                                  L"ProgramData"};
    for (const wchar_t* name : variables) {
        wchar_t value[MAX_PATH] = {0};
        const DWORD length = GetEnvironmentVariableW(name, value, MAX_PATH);
        if (length == 0 || length >= MAX_PATH) {
            continue;
        }
        DWORD error = ERROR_SUCCESS;
        const std::wstring canonical = CanonicalPath(value, &error);
        if (canonical.empty()) {
            continue;
        }
        if (IsUnderOrEqual(path, canonical)) {
            return true;
        }
    }
    return false;
}

}  // namespace

const wchar_t* PhaseText(Phase phase) {
    switch (phase) {
        case Phase::Validate:
            return L"Проверка условий";
        case Phase::Scan:
            return L"Подготовка списка файлов";
        case Phase::Copy:
            return L"Копирование";
        case Phase::Verify:
            return L"Сверка копии";
        case Phase::Publish:
            return L"Публикация копии";
        case Phase::Link:
            return L"Создание ссылки";
        case Phase::Cleanup:
            return L"Удаление старого экземпляра";
        case Phase::Done:
            return L"Готово";
        case Phase::Failed:
            return L"Ошибка";
        case Phase::Cancelled:
            return L"Отменено";
    }
    return L"";
}

Plan BuildPlan(const std::wstring& source_input, const std::wstring& dest_parent_input) {
    Plan plan;
    const std::wstring source_text = TrimPathInput(source_input);
    const std::wstring dest_text = TrimPathInput(dest_parent_input);
    if (source_text.empty()) {
        plan.error = L"Укажите папку, которую нужно перенести.";
        return plan;
    }
    if (dest_text.empty()) {
        plan.error = L"Укажите папку назначения.";
        return plan;
    }
    DWORD error = ERROR_SUCCESS;
    const DWORD source_input_attrs = PathAttributes(TrimPathInput(source_text));
    if (source_input_attrs == INVALID_FILE_ATTRIBUTES) {
        plan.error = L"Исходная папка недоступна: " + TrimPathInput(source_text);
        return plan;
    }
    if ((source_input_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        plan.error = L"Исходная папка уже является ссылкой: " + TrimPathInput(source_text);
        return plan;
    }
    if ((source_input_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        plan.error = L"Исходный путь должен быть папкой: " + TrimPathInput(source_text);
        return plan;
    }
    const DWORD dest_input_attrs = PathAttributes(TrimPathInput(dest_text));
    if (dest_input_attrs == INVALID_FILE_ATTRIBUTES) {
        plan.error = L"Папка назначения недоступна: " + TrimPathInput(dest_text);
        return plan;
    }
    if ((dest_input_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        plan.error = L"Нельзя переносить в ссылку, выберите обычную папку: " + TrimPathInput(dest_text);
        return plan;
    }
    const std::wstring source = CanonicalPath(source_text, &error);
    if (source.empty()) {
        plan.error = L"Не удалось открыть исходную папку: " + Win32ErrorText(error);
        return plan;
    }
    const std::wstring dest_parent = CanonicalPath(dest_text, &error);
    if (dest_parent.empty()) {
        plan.error = L"Не удалось открыть папку назначения: " + Win32ErrorText(error);
        return plan;
    }
    if (source.size() <= 3) {
        plan.error = L"Нельзя переносить корень диска: " + source;
        return plan;
    }
    const DWORD source_attrs = PathAttributes(source);
    if (source_attrs == INVALID_FILE_ATTRIBUTES) {
        plan.error = L"Исходная папка недоступна: " + source;
        return plan;
    }
    if ((source_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        plan.error = L"Исходный путь должен быть папкой: " + source;
        return plan;
    }
    if ((source_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        plan.error = L"Исходная папка уже является ссылкой: " + source;
        return plan;
    }
    const DWORD dest_attrs = PathAttributes(dest_parent);
    if (dest_attrs == INVALID_FILE_ATTRIBUTES) {
        plan.error = L"Папка назначения недоступна: " + dest_parent;
        return plan;
    }
    if ((dest_attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        plan.error = L"Место назначения должно быть папкой: " + dest_parent;
        return plan;
    }
    if ((dest_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        plan.error = L"Нельзя переносить в ссылку, выберите обычную папку: " + dest_parent;
        return plan;
    }
    const std::wstring name = LeafName(source);
    if (name.empty() || name == L"." || name == L"..") {
        plan.error = L"Не удалось определить имя переносимой папки.";
        return plan;
    }
    const std::wstring dest_final = JoinPath(dest_parent, name);
    if (!PathsEqual(ParentPath(dest_final), dest_parent)) {
        plan.error = L"Некорректный путь назначения: " + dest_final;
        return plan;
    }
    if (PathExists(dest_final)) {
        plan.error = L"На новом месте уже есть объект с именем «" + name + L"»: " + dest_final +
                     L"\n\nНичего не перезаписывается. Укажите другую папку назначения.";
        return plan;
    }
    if (IsUnderOrEqual(dest_parent, source)) {
        plan.error = L"Папка назначения находится внутри переносимой папки.";
        return plan;
    }
    if (IsUnderOrEqual(source, dest_final)) {
        plan.error = L"Исходная папка находится внутри папки назначения.";
        return plan;
    }
    if (IsCriticalDirectory(source)) {
        plan.error = L"Нельзя переносить системные каталоги Windows: " + source;
        return plan;
    }
    {
        wchar_t profile[MAX_PATH] = {0};
        const DWORD length = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            DWORD profile_error = ERROR_SUCCESS;
            const std::wstring profile_path = CanonicalPath(profile, &profile_error);
            if (!profile_path.empty() && PathsEqual(source, profile_path)) {
                plan.error = L"Нельзя переносить папку профиля пользователя целиком: " + source +
                             L"\nВыберите вложенную папку.";
                return plan;
            }
        }
    }
    std::wstring volume_error;
    if (!IsLocalNtfs(source, volume_error)) {
        plan.error = L"Исходная папка: " + volume_error;
        return plan;
    }
    if (!IsLocalNtfs(dest_parent, volume_error)) {
        plan.error = L"Папка назначения: " + volume_error;
        return plan;
    }
    plan.valid = true;
    plan.source = source;
    plan.source_parent = ParentPath(source);
    plan.name = name;
    plan.dest_parent = dest_parent;
    plan.dest_final = dest_final;
    plan.staging = JoinPath(dest_parent, L".linkerino-stage-" + NewGuidString());
    plan.backup = JoinPath(plan.source_parent, L".linkerino-backup-" + NewGuidString());
    return plan;
}

Outcome Execute(const Plan& plan, ProgressSink* sink, const Faults& faults) {
    Outcome outcome;
    outcome.dest_final = plan.dest_final;
    if (!plan.valid) {
        outcome.message = L"Проверка путей не пройдена.";
        outcome.detail = plan.error;
        return outcome;
    }
    CopyContext context;
    context.sink = sink;
    const std::wstring journal_id = NewGuidString();
    WriteJournal(journal_id, plan, L"start", L"");

    auto finish_error = [&](const std::wstring& message, const std::wstring& detail, const std::wstring& state) {
        outcome.ok = false;
        outcome.message = message;
        outcome.detail = detail;
        WriteJournal(journal_id, plan, state, L"error=" + detail);
        LogLine(L"FAIL " + message + L" | " + detail);
        return outcome;
    };

    LogLine(L"START source=" + plan.source + L" dest=" + plan.dest_final);
    std::wstring error;

    context.phase = Phase::Validate;
    context.current = L"Проверка прав на ссылку";
    context.Report(true);
    DWORD link_error_code = ERROR_SUCCESS;
    if (!ProbeSymlink(plan.source_parent, plan.dest_final, error, &link_error_code)) {
        outcome.message = L"Не удалось проверить возможность создать ссылку. Перенос не начат, данные не тронуты.";
        outcome.needs_elevation = link_error_code == ERROR_PRIVILEGE_NOT_HELD;
        return finish_error(outcome.message, error, L"failed");
    }
    if (PathExists(plan.backup)) {
        return finish_error(L"Служебное имя для резерва уже занято. Перенос не начат.", plan.backup, L"failed");
    }
    if (PathExists(plan.staging)) {
        return finish_error(L"Служебная папка уже существует. Перенос не начат.", plan.staging, L"failed");
    }
    if (!CreateDirectoryW(ApiPath(plan.staging).c_str(), nullptr)) {
        return finish_error(L"Не удалось создать временную папку на новом месте. Данные не тронуты.",
                            Win32ErrorText(GetLastError()), L"failed");
    }
    WriteJournal(journal_id, plan, L"copying", L"");

    auto cleanup_staging = [&]() {
        std::wstring cleanup_error;
        if (RemoveTreeNoFollow(plan.staging, cleanup_error)) {
            return;
        }
        outcome.leftover = plan.staging;
        LogLine(L"staging cleanup failed: " + cleanup_error);
    };

    context.phase = Phase::Scan;
    context.current = plan.source;
    context.Report(true);
    std::vector<Entry> entries;
    if (!ScanDir(plan.source, L"", 0, entries, error)) {
        cleanup_staging();
        outcome.message =
            L"Перенос остановлен до копирования: в папке есть неподдерживаемые объекты. Оригинал не изменён.";
        return finish_error(outcome.message, error, L"failed");
    }
    std::uint64_t total_bytes = 0;
    std::uint64_t total_files = 0;
    for (const Entry& entry : entries) {
        if (!entry.is_dir) {
            total_bytes += entry.WorkBytes();
            ++total_files;
        }
    }
    context.bytes_total = total_bytes;
    context.files_total = total_files;
    ULARGE_INTEGER free_bytes = {};
    bool have_free_bytes = false;
    const std::wstring dest_root = VolumeRootOf(plan.dest_parent);
    if (!dest_root.empty() && GetDiskFreeSpaceExW(dest_root.c_str(), &free_bytes, nullptr, nullptr)) {
        have_free_bytes = true;
    }
    if (faults.low_space) {
        free_bytes.QuadPart = 0;
        have_free_bytes = true;
    }
    if (have_free_bytes && total_bytes > free_bytes.QuadPart) {
        cleanup_staging();
        outcome.message = L"На новом диске недостаточно свободного места. Оригинал не изменён.";
        return finish_error(outcome.message,
                            L"Нужно " + std::to_wstring(total_bytes) + L" байт, свободно " +
                                std::to_wstring(free_bytes.QuadPart),
                            L"failed");
    }

    context.phase = Phase::Copy;
    context.current.clear();
    context.Report(true);
    if (!CopyTree(plan, entries, context, faults, error)) {
        cleanup_staging();
        if (context.cancelled) {
            outcome.cancelled = true;
            outcome.message = L"Отменено до изменения исходной папки. Оригинал на месте.";
            outcome.detail = error;
            WriteJournal(journal_id, plan, L"cancelled", L"error=" + error);
            LogLine(L"CANCELLED during copy");
            return outcome;
        }
        outcome.message = L"Копирование не завершено. Оригинал не изменён.";
        return finish_error(outcome.message, error, L"failed");
    }
    if (faults.touch_source_after_copy) {
        for (const Entry& entry : entries) {
            if (!entry.is_dir) {
                AppendProbeByte(JoinPath(plan.source, entry.rel));
                break;
            }
        }
    }

    context.phase = Phase::Verify;
    context.bytes_done = 0;
    context.Report(true);
    if (!VerifyTree(plan.staging, entries, context, error)) {
        if (context.cancelled) {
            cleanup_staging();
            outcome.cancelled = true;
            outcome.message = L"Отменено во время сверки. Оригинал на месте.";
            WriteJournal(journal_id, plan, L"cancelled", L"error=" + error);
            return outcome;
        }
        cleanup_staging();
        outcome.message = L"Сверка копии не прошла. Оригинал не изменён.";
        return finish_error(outcome.message, error, L"failed");
    }
    if (faults.verify_mismatch) {
        cleanup_staging();
        outcome.message = L"Сверка копии не прошла. Оригинал не изменён.";
        return finish_error(outcome.message, L"Тестовый сбой сверки", L"failed");
    }
    if (!VerifySourceUnchanged(plan, entries, error)) {
        cleanup_staging();
        outcome.message = L"Исходная папка изменилась во время переноса. Оригинал не тронут.";
        return finish_error(outcome.message, error, L"failed");
    }
    WriteJournal(journal_id, plan, L"verified", L"files=" + std::to_wstring(total_files));

    context.phase = Phase::Publish;
    context.current = plan.dest_final;
    context.Report(true);
    DWORD publish_error = ERROR_SUCCESS;
    if (!RenameWithRetry(plan.staging, plan.dest_final, &publish_error)) {
        outcome.leftover = plan.staging;
        outcome.message = L"Не удалось опубликовать копию под новым именем. Оригинал не изменён, копия сохранена.";
        return finish_error(outcome.message, Win32ErrorText(publish_error), L"failed");
    }
    std::uint64_t dest_serial = 0;
    std::uint64_t dest_index = 0;
    if (!ReadIdentity(plan.dest_final, dest_serial, dest_index, error)) {
        outcome.leftover = plan.dest_final;
        outcome.message = L"Копия опубликована, но проверить её не удалось. Оригинал не изменён.";
        return finish_error(outcome.message, error, L"published");
    }
    FlushVolume(plan.dest_final);
    WriteJournal(journal_id, plan, L"published",
                 L"volume=" + std::to_wstring(dest_serial) + L" index=" + std::to_wstring(dest_index));
    if (faults.tamper_after_publish) {
        for (const Entry& entry : entries) {
            if (!entry.is_dir) {
                AppendProbeByte(JoinPath(plan.dest_final, entry.rel));
                break;
            }
        }
    }

    context.phase = Phase::Link;
    context.current = plan.source;
    context.Report(true);
    DWORD backup_error = ERROR_SUCCESS;
    if (!RenameWithRetry(plan.source, plan.backup, &backup_error)) {
        outcome.leftover = plan.dest_final;
        outcome.message = L"Копия готова, но переименовать оригинал не удалось. Исходная папка не изменена.";
        return finish_error(outcome.message, Win32ErrorText(backup_error), L"published");
    }
    WriteJournal(journal_id, plan, L"backup", L"");

    bool link_ok = false;
    if (faults.link_failure) {
        error = L"Тестовый сбой создания ссылки";
    } else {
        link_ok = CreateSymlinkCompat(plan.source, plan.dest_final, error);
    }
    if (!link_ok) {
        if (MoveFileExW(ApiPath(plan.backup).c_str(), ApiPath(plan.source).c_str(), 0)) {
            outcome.leftover = plan.dest_final;
            outcome.message =
                L"Ссылку создать не удалось. Исходная папка восстановлена, проверенная копия осталась на новом месте.";
            return finish_error(outcome.message, error, L"relink-failed");
        }
        outcome.leftover = plan.backup;
        outcome.message =
            L"Ссылку создать не удалось, и вернуть исходное имя автоматически не получилось. Данные целы в двух местах.";
        return finish_error(outcome.message, error + L"; резерв: " + plan.backup, L"relink-failed");
    }
    if (!VerifySymlink(plan.source, plan.dest_final, dest_serial, dest_index, error)) {
        RemoveDirectoryW(ApiPath(plan.source).c_str());
        if (MoveFileExW(ApiPath(plan.backup).c_str(), ApiPath(plan.source).c_str(), 0)) {
            outcome.leftover = plan.dest_final;
            outcome.message = L"Ссылка не прошла проверку и удалена. Исходная папка восстановлена.";
            return finish_error(outcome.message, error, L"relink-failed");
        }
        outcome.leftover = plan.backup;
        outcome.message = L"Ссылка не прошла проверку. Данные целы, но исходное имя занято ссылкой.";
        return finish_error(outcome.message, error, L"relink-failed");
    }
    WriteJournal(journal_id, plan, L"linked", L"");

    context.phase = Phase::Cleanup;
    context.current = plan.dest_final;
    context.Report(true);
    CopyContext cleanup_context;
    cleanup_context.phase = Phase::Cleanup;
    cleanup_context.bytes_total = total_bytes;
    if (faults.break_link_before_delete) {
        RemoveDirectoryW(ApiPath(plan.source).c_str());
    }
    std::wstring link_check_error;
    if (!VerifySymlink(plan.source, plan.dest_final, dest_serial, dest_index, link_check_error)) {
        outcome.leftover = plan.backup;
        outcome.message = L"Ссылка на старом месте недоступна, старый экземпляр не удалён. Данные сохранены.";
        return finish_error(outcome.message, link_check_error, L"link-lost");
    }
    if (!VerifyTree(plan.dest_final, entries, cleanup_context, error)) {
        outcome.leftover = plan.backup;
        outcome.message =
            L"Копия изменилась после публикации. Старый экземпляр не удалён, данные сохранены.";
        return finish_error(outcome.message, error, L"cleanup-skipped");
    }
    const bool durability_confirmed = !faults.force_flush_failure && FlushVolume(plan.dest_final);
    if (!durability_confirmed) {
        outcome.ok = true;
        outcome.leftover = plan.backup;
        outcome.message =
            L"Перенос выполнен, ссылка работает. Подтвердить запись на диск не удалось, поэтому старый экземпляр "
            L"сохранён и не удалён.";
        WriteJournal(journal_id, plan, L"cleanup-skipped-durability", L"volume-flush-failed");
        LogLine(L"durability not confirmed, backup kept: " + plan.backup);
        return outcome;
    }
    std::wstring stopped_at;
    bool link_lost = false;
    if (!DeleteBackupTree(plan.backup, entries, plan.source, plan.dest_final, dest_serial, dest_index, faults, error,
                          stopped_at, link_lost)) {
        outcome.ok = !link_lost;
        outcome.leftover = stopped_at;
        outcome.message = link_lost
                              ? L"Ссылка на старом месте перестала работать. Удаление старого экземпляра остановлено, "
                                L"остаток сохранён: " +
                                    stopped_at
                              : L"Перенос выполнен, ссылка работает. Старый экземпляр удалён не полностью: " + error;
        outcome.detail = error;
        WriteJournal(journal_id, plan, link_lost ? L"link-lost" : L"cleanup-partial", L"error=" + error);
        LogLine((link_lost ? L"LINK LOST during cleanup: " : L"PARTIAL cleanup: ") + error);
        return outcome;
    }
    RemoveJournal(journal_id);
    outcome.ok = true;
    outcome.message = L"Готово. Папка перенесена, на старом месте — ссылка на новое место.";
    LogLine(L"OK source=" + plan.source + L" dest=" + plan.dest_final);
    return outcome;
}
std::vector<std::wstring> FindUnfinishedJournals() {
    std::vector<std::wstring> result;
    const std::wstring dir = JournalDirectory();
    if (dir.empty()) {
        return result;
    }
    WIN32_FIND_DATAW find_data = {};
    FindHandle find(FindFirstFileExW(ApiPath(JoinPath(dir, L"journal-*.txt")).c_str(), FindExInfoBasic, &find_data,
                                 FindExSearchNameMatch, nullptr, 0));
    if (!find.valid()) {
        return result;
    }
    do {
        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            result.push_back(JoinPath(dir, find_data.cFileName));
        }
    } while (FindNextFileW(find.get(), &find_data));
    std::sort(result.begin(), result.end());
    return result;
}

std::wstring ReadJournalText(const std::wstring& path) {
    Handle file(CreateFileW(ApiPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return std::wstring();
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) {
        return std::wstring();
    }
    std::string data(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.get(), &data[0], static_cast<DWORD>(data.size()), &read, nullptr)) {
        return std::wstring();
    }
    data.resize(read);
    return FromUtf8(data);
}

}  // namespace linkerino
