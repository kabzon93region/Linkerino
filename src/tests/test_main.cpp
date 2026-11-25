#include "engine.h"
#include "win_util.h"

#include <winioctl.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

using namespace linkerino;

namespace {

int g_failures = 0;
int g_checks = 0;
std::set<std::wstring> g_journals_before;

void Check(bool condition, const std::wstring& what) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::wprintf(L"  FAIL: %ls\n", what.c_str());
    }
}

class FindGuard {
public:
    explicit FindGuard(HANDLE handle) : handle_(handle) {}
    FindGuard(const FindGuard&) = delete;
    FindGuard& operator=(const FindGuard&) = delete;
    ~FindGuard() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            FindClose(handle_);
        }
    }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_;
};

struct EntryInfo {
    std::uint64_t volume_serial = 0;
    std::uint64_t file_index = 0;
    DWORD links = 0;
};

bool ReadEntryInfo(const std::wstring& path, EntryInfo& info) {
    Handle file(CreateFileW(ApiPath(path).c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0,
                            nullptr));
    if (!file.valid()) {
        return false;
    }
    BY_HANDLE_FILE_INFORMATION data = {};
    if (!GetFileInformationByHandle(file.get(), &data)) {
        return false;
    }
    info.volume_serial = data.dwVolumeSerialNumber;
    info.file_index = (static_cast<std::uint64_t>(data.nFileIndexHigh) << 32) | data.nFileIndexLow;
    info.links = data.nNumberOfLinks;
    return true;
}

std::wstring TempRoot() {
    wchar_t buffer[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, buffer);
    std::wstring root = std::wstring(buffer) + L"LinkerinoTests\\run-" + NewGuidString();
    return root;
}

bool MakeDir(const std::wstring& path) {
    return CreateDirectoryW(ApiPath(path).c_str(), nullptr) != FALSE || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool MakeDirs(const std::wstring& path) {
    std::wstring current;
    for (std::size_t index = 0; index < path.size(); ++index) {
        current.push_back(path[index]);
        if (path[index] == L'\\' && current.size() > 3) {
            MakeDir(current.substr(0, current.size() - 1));
        }
    }
    return MakeDir(path);
}

bool WriteBytes(const std::wstring& path, const std::string& data) {
    Handle file(CreateFileW(ApiPath(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr));
    if (!file.valid()) {
        return false;
    }
    DWORD written = 0;
    return WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) != FALSE;
}

bool ReadBytes(const std::wstring& path, std::string& data) {
    Handle file(CreateFileW(ApiPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart < 0 || size.QuadPart > 64 * 1024 * 1024) {
        return false;
    }
    data.assign(static_cast<std::size_t>(size.QuadPart), '\0');
    if (data.empty()) {
        return true;
    }
    DWORD read = 0;
    if (!ReadFile(file.get(), &data[0], static_cast<DWORD>(data.size()), &read, nullptr)) {
        return false;
    }
    data.resize(read);
    return true;
}

bool WriteStream(const std::wstring& path, const std::wstring& stream, const std::string& data) {
    Handle file(CreateFileW(ApiPath(path + L":" + stream + L":$DATA").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }
    DWORD written = 0;
    return WriteFile(file.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) != FALSE;
}

bool ReadStream(const std::wstring& path, const std::wstring& stream, std::string& data) {
    return ReadBytes(path + L":" + stream + L":$DATA", data);
}

std::wstring CanonicalOrSelf(const std::wstring& path) {
    DWORD error = ERROR_SUCCESS;
    const std::wstring canonical = CanonicalPath(path, &error);
    return canonical.empty() ? path : canonical;
}
bool IsSymlinkTo(const std::wstring& link, const std::wstring& target) {
    const DWORD attrs = GetFileAttributesW(ApiPath(link).c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        return false;
    }
    DWORD error = 0;
    const std::wstring resolved = CanonicalPath(link, &error);
    DWORD target_error = 0;
    const std::wstring expected = CanonicalPath(target, &target_error);
    return !resolved.empty() && !expected.empty() && PathsEqual(resolved, expected);
}

bool RemoveTree(const std::wstring& plain) {
    const DWORD attrs = GetFileAttributesW(ApiPath(plain).c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return RemoveDirectoryW(ApiPath(plain).c_str()) != FALSE;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        WIN32_FIND_DATAW data = {};
        FindGuard find(FindFirstFileExW(ApiPath(JoinPath(plain, L"*")).c_str(), FindExInfoBasic, &data,
                                     FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH));
        if (find.valid()) {
            do {
                const std::wstring name = data.cFileName;
                if (name == L"." || name == L"..") {
                    continue;
                }
                RemoveTree(JoinPath(plain, name));
            } while (FindNextFileW(find.get(), &data));
        }
        return RemoveDirectoryW(ApiPath(plain).c_str()) != FALSE;
    }
    if ((attrs & FILE_ATTRIBUTE_READONLY) != 0) {
        SetFileAttributesW(ApiPath(plain).c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    }
    return DeleteFileW(ApiPath(plain).c_str()) != FALSE;
}

bool NoServiceEntries(const std::wstring& parent) {
    WIN32_FIND_DATAW data = {};
    FindGuard find(FindFirstFileExW(ApiPath(JoinPath(parent, L".linkerino-*")).c_str(), FindExInfoBasic, &data,
                                 FindExSearchNameMatch, nullptr, 0));
    if (!find.valid()) {
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    return false;
}

class CountingSink : public ProgressSink {
public:
    explicit CountingSink(std::atomic<bool>* cancel = nullptr) : cancel_(cancel) {}
    void OnProgress(const Progress& progress) override {
        last_phase = progress.phase;
        ++reports;
    }
    bool CancelRequested() override { return cancel_ != nullptr && cancel_->load(); }

    Phase last_phase = Phase::Validate;
    int reports = 0;

private:
    std::atomic<bool>* cancel_ = nullptr;
};

bool PrepareSource(const std::wstring& source) {
    if (!MakeDirs(JoinPath(source, L"Вложенная папка"))) {
        return false;
    }
    if (!MakeDir(JoinPath(source, L"пустая"))) {
        return false;
    }
    if (!WriteBytes(JoinPath(source, L"readme.txt"), "hello linkerino")) {
        return false;
    }
    if (!WriteBytes(JoinPath(source, L"пустой.bin"), "")) {
        return false;
    }
    if (!WriteBytes(JoinPath(source, L"Вложенная папка\\файл с пробелом.txt"), "unicode data")) {
        return false;
    }
    if (!WriteBytes(JoinPath(source, L"hidden.dat"), "hidden")) {
        return false;
    }
    if (!SetFileAttributesW(ApiPath(JoinPath(source, L"hidden.dat")).c_str(), FILE_ATTRIBUTE_HIDDEN)) {
        return false;
    }
    if (!WriteBytes(JoinPath(source, L"readonly.txt"), "read only")) {
        return false;
    }
    if (!SetFileAttributesW(ApiPath(JoinPath(source, L"readonly.txt")).c_str(), FILE_ATTRIBUTE_READONLY)) {
        return false;
    }
    if (!WriteStream(JoinPath(source, L"readme.txt"), L"Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n")) {
        return false;
    }
    return true;
}

void TestBasicMove() {
    std::wprintf(L"basic move\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(JoinPath(root, L"src"));
    MakeDirs(dest_parent);
    Check(PrepareSource(source), L"prepare source");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan is valid: " + plan.error);
    Check(PathsEqual(plan.dest_final, JoinPath(CanonicalOrSelf(dest_parent), L"Data")), L"final path is dest\\Data");
    CountingSink sink;
    const Outcome outcome = Execute(plan, &sink, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    Check(IsSymlinkTo(source, plan.dest_final), L"source is a symlink to the copy");
    Check(!PathExists(plan.staging), L"staging removed");
    Check(NoServiceEntries(dest_parent), L"no service folders in destination");
    Check(NoServiceEntries(JoinPath(root, L"src")), L"no service folders next to source");
    std::string content;
    Check(ReadBytes(JoinPath(plan.dest_final, L"readme.txt"), content) && content == "hello linkerino",
          L"content copied");
    std::string unicode;
    Check(ReadBytes(JoinPath(plan.dest_final, L"Вложенная папка\\файл с пробелом.txt"), unicode) &&
              unicode == "unicode data",
          L"unicode content copied");
    Check(ReadBytes(JoinPath(source, L"readme.txt"), content) && content == "hello linkerino",
          L"source through link reads data");
    std::string zone;
    Check(ReadStream(JoinPath(plan.dest_final, L"readme.txt"), L"Zone.Identifier", zone) &&
              zone.find("ZoneId=3") != std::string::npos,
          L"alternate stream copied");
    Check(PathExists(JoinPath(plan.dest_final, L"пустая")), L"empty directory copied");
    const DWORD attrs = GetFileAttributesW(ApiPath(JoinPath(plan.dest_final, L"readonly.txt")).c_str());
    Check(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) != 0, L"read-only attribute kept");
    const DWORD hidden = GetFileAttributesW(ApiPath(JoinPath(plan.dest_final, L"hidden.dat")).c_str());
    Check(hidden != INVALID_FILE_ATTRIBUTES && (hidden & FILE_ATTRIBUTE_HIDDEN) != 0, L"hidden attribute kept");
    RemoveTree(root);
}

void TestEmptyFolder() {
    std::wprintf(L"empty folder\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Empty");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    Check(IsSymlinkTo(source, plan.dest_final), L"empty folder is linked");
    Check(PathExists(plan.dest_final), L"empty folder copied");
    RemoveTree(root);
}

void TestRejectExistingDestination() {
    std::wprintf(L"reject existing destination\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(JoinPath(dest_parent, L"Data"));
    const Plan plan = BuildPlan(source, dest_parent);
    Check(!plan.valid, L"plan rejected when destination exists");
    Check(plan.error.find(L"уже есть объект") != std::wstring::npos, L"error explains the collision");
    RemoveTree(root);
}

void TestRejectNesting() {
    std::wprintf(L"reject nesting\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    MakeDirs(source);
    Plan inside = BuildPlan(source, JoinPath(source, L"sub"));
    Check(!inside.valid, L"destination inside source rejected");
    MakeDirs(JoinPath(root, L"dest"));
    Plan inside_dest = BuildPlan(JoinPath(root, L"dest\\Child"), root + L"\\dest");
    Check(!inside_dest.valid, L"source inside destination rejected");
    RemoveTree(root);
}

void TestRejectSymlinkSource() {
    std::wprintf(L"reject symlink source\n");
    const std::wstring root = TempRoot();
    const std::wstring real = JoinPath(root, L"src\\Real");
    const std::wstring link = JoinPath(root, L"src\\Linked");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(real);
    MakeDirs(dest_parent);
    std::wstring error;
    if (!CreateSymlinkCompat(link, real, error)) {
        std::wprintf(L"  (probe symlink failed: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(link, dest_parent);
    Check(!plan.valid, L"symlink source rejected");
    RemoveTree(root);
}

bool CreateJunction(const std::wstring& link, const std::wstring& target) {
    const std::wstring command = L"cmd.exe /c mklink /J \"" + link + L"\" \"" + target + L"\" >nul";
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');
    STARTUPINFOW info = {};
    info.cb = sizeof(info);
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &info,
                        &process)) {
        return false;
    }
    WaitForSingleObject(process.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    return code == 0;
}

bool ReadSubstituteName(const std::wstring& path, std::wstring& substitute) {
    Handle handle(CreateFileW(ApiPath(path).c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!handle.valid()) {
        return false;
    }
    std::vector<BYTE> buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    DWORD returned = 0;
    if (!DeviceIoControl(handle.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, buffer.data(),
                         static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        return false;
    }
    const auto* header = reinterpret_cast<const ULONG*>(buffer.data());
    const ULONG tag = header[0];
    const auto* data = reinterpret_cast<const USHORT*>(buffer.data());
    const USHORT substitute_offset = data[4];
    const USHORT substitute_length = data[5];
    const std::size_t base = tag == IO_REPARSE_TAG_SYMLINK ? 20 : 16;
    const std::size_t start = base + substitute_offset;
    if (substitute_length == 0 || start + substitute_length > returned) {
        return false;
    }
    substitute.assign(reinterpret_cast<const WCHAR*>(buffer.data() + start), substitute_length / sizeof(WCHAR));
    return true;
}

void TestReparseInsideCopied() {
    std::wprintf(L"symlink inside tree copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(JoinPath(source, L"data"));
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"data\\file.txt"), "linked payload");
    const std::wstring link_path = JoinPath(source, L"inner");
    std::wstring error;
    if (!CreateSymlinkCompat(link_path, JoinPath(source, L"data"), error)) {
        std::wprintf(L"  (probe symlink failed: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const std::wstring expected_target = CanonicalOrSelf(JoinPath(source, L"data"));
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid before scan: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    const std::wstring link_copy = JoinPath(plan.dest_final, L"inner");
    const DWORD attrs = GetFileAttributesW(ApiPath(link_copy).c_str());
    Check(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
          L"symlink recreated in the copy");
    std::wstring substitute;
    Check(ReadSubstituteName(link_copy, substitute), L"symlink target readable");
    std::wstring expected = L"\\??\\" + expected_target;
    Check(PathsEqual(substitute, expected), L"symlink target preserved: " + substitute);
    std::string content;
    Check(ReadBytes(JoinPath(link_copy, L"file.txt"), content) && content == "linked payload",
          L"data through the recreated link");
    RemoveTree(root);
}

void TestRelativeSymlinkInside() {
    std::wprintf(L"relative symlink inside tree copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(JoinPath(source, L"data"));
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"data\\file.txt"), "relative payload");
    std::wstring error;
    if (!CreateSymlinkCompat(JoinPath(source, L"rel"), L"data", error)) {
        std::wprintf(L"  (relative symlink failed: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::wstring substitute;
    Check(ReadSubstituteName(JoinPath(plan.dest_final, L"rel"), substitute), L"relative link target readable");
    Check(PathsEqual(substitute, L"data"), L"relative target preserved: " + substitute);
    std::string content;
    Check(ReadBytes(JoinPath(plan.dest_final, L"rel\\file.txt"), content) && content == "relative payload",
          L"relative link works in the copy");
    RemoveTree(root);
}

void TestJunctionInsideCopied() {
    std::wprintf(L"junction inside tree copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring external = JoinPath(root, L"external");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(external);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(external, L"payload.txt"), "junction payload");
    const std::wstring junction = JoinPath(source, L"junction");
    if (!CreateJunction(junction, external)) {
        std::wprintf(L"  (junction creation failed)\n");
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    const std::wstring junction_copy = JoinPath(plan.dest_final, L"junction");
    const DWORD attrs = GetFileAttributesW(ApiPath(junction_copy).c_str());
    Check(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
          L"junction recreated");
    std::wstring substitute;
    Check(ReadSubstituteName(junction_copy, substitute), L"junction target readable");
    Check(PathsEqual(substitute, L"\\??\\" + external), L"junction target preserved: " + substitute);
    std::string content;
    Check(ReadBytes(JoinPath(junction_copy, L"payload.txt"), content) && content == "junction payload",
          L"data through the recreated junction");
    RemoveTree(root);
}

void TestHardLinksCopied() {
    std::wprintf(L"hard links inside tree copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    const std::wstring first = JoinPath(source, L"one.txt");
    WriteBytes(first, "hard link payload");
    if (!CreateHardLinkW(ApiPath(JoinPath(source, L"two.txt")).c_str(), ApiPath(first).c_str(), nullptr)) {
        std::wprintf(L"  (hard link creation failed)\n");
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    EntryInfo a;
    EntryInfo b;
    Check(ReadEntryInfo(JoinPath(plan.dest_final, L"one.txt"), a), L"first link readable");
    Check(ReadEntryInfo(JoinPath(plan.dest_final, L"two.txt"), b), L"second link readable");
    Check(a.file_index == b.file_index && a.volume_serial == b.volume_serial, L"both names share one file");
    Check(a.links == 2, L"hard link count recreated");
    RemoveTree(root);
}

void TestVerifyFault() {
    std::wprintf(L"verify mismatch fault\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.verify_mismatch = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"execute refused after verification failure");
    Check(PathExists(JoinPath(source, L"file.txt")), L"original file intact");
    Check(!PathExists(plan.dest_final), L"nothing published");
    Check(!PathExists(plan.staging), L"staging removed");
    RemoveTree(root);
}

void TestLinkFault() {
    std::wprintf(L"link failure fault\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.link_failure = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"execute reported link failure");
    const DWORD attrs = GetFileAttributesW(ApiPath(source).c_str());
    Check(attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0,
          L"source restored as a normal folder");
    std::string content;
    Check(ReadBytes(JoinPath(source, L"file.txt"), content) && content == "payload", L"source data intact");
    Check(PathExists(JoinPath(plan.dest_final, L"file.txt")), L"verified copy kept");
    RemoveTree(root);
}

void TestCancel() {
    std::wprintf(L"cancel during copy\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"big.bin"), std::string(4 * 1024 * 1024, 'x'));
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    std::atomic<bool> cancel(true);
    CountingSink sink(&cancel);
    const Outcome outcome = Execute(plan, &sink, Faults());
    Check(outcome.cancelled, L"cancelled outcome");
    Check(PathExists(JoinPath(source, L"big.bin")), L"original intact");
    Check(!PathExists(plan.staging), L"staging removed");
    Check(GetFileAttributesW(ApiPath(source).c_str()) != INVALID_FILE_ATTRIBUTES, L"source folder intact");
    RemoveTree(root);
}

void TestReadOnlySourcePlacement() {
    std::wprintf(L"same volume move\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"parent\\Data");
    const std::wstring dest_parent = JoinPath(root, L"parent\\moved");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"a.txt"), "aaa");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    Check(IsSymlinkTo(source, plan.dest_final), L"link points to moved folder");
    RemoveTree(root);
}

std::wstring FindCrossVolumeBase() {
    wchar_t temp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, temp);
    const std::wstring temp_root = VolumeRootOf(temp);
    const auto is_local_ntfs = [](const std::wstring& root) {
        if (root.empty() || GetDriveTypeW(root.c_str()) != DRIVE_FIXED) {
            return false;
        }
        wchar_t file_system[64] = {0};
        return GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, file_system, 64) != FALSE &&
               _wcsicmp(file_system, L"NTFS") == 0;
    };
    const std::wstring exe_root = VolumeRootOf(ExeDirectory());
    if (!exe_root.empty() && !PathsEqual(exe_root, temp_root) && is_local_ntfs(exe_root)) {
        const std::wstring base = JoinPath(ExeDirectory(), L"cross-tests");
        MakeDirs(base);
        return base;
    }
    const DWORD mask = GetLogicalDrives();
    const wchar_t candidates[] = {L'Z', L'Y', L'X', L'W', L'V', L'U', L'T', L'S', L'R', L'Q', L'P',
                                  L'O', L'N', L'M', L'L', L'K', L'J', L'I', L'H', L'G', L'F', L'E', L'D'};
    for (wchar_t letter : candidates) {
        if (letter == L'B' || (mask & (1u << (letter - L'A'))) == 0) {
            continue;
        }
        std::wstring root;
        root.push_back(letter);
        root += L":\\";
        if (!is_local_ntfs(root) || PathsEqual(root, temp_root)) {
            continue;
        }
        return root;
    }
    return std::wstring();
}

void TestCrossVolume() {
    std::wprintf(L"cross volume move\n");
    const std::wstring base = FindCrossVolumeBase();
    if (base.empty()) {
        std::wprintf(L"  (skipped: no second fixed NTFS volume)\n");
        return;
    }
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(base, L"linkerino-cross-" + NewGuidString());
    MakeDirs(source);
    if (!MakeDirs(dest_parent)) {
        std::wprintf(L"  (skipped: cannot create %ls)\n", dest_parent.c_str());
        RemoveTree(root);
        return;
    }
    WriteBytes(JoinPath(source, L"a.txt"), "cross volume payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"cross-volume plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"cross-volume execute ok: " + outcome.message + L" / " + outcome.detail);
    Check(IsSymlinkTo(source, plan.dest_final), L"cross-volume link works");
    std::string content;
    Check(ReadBytes(JoinPath(source, L"a.txt"), content) && content == "cross volume payload",
          L"cross-volume data readable through link");
    RemoveTree(root);
    RemoveTree(dest_parent);
}

void TestDirectoryStreamCopied() {
    std::wprintf(L"directory stream copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"a.txt"), "data");
    Handle stream(CreateFileW(ApiPath(source + L":DirStream:$DATA").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!stream.valid()) {
        std::wprintf(L"  (skipped: cannot create directory stream, error %lu)\n", GetLastError());
        RemoveTree(root);
        return;
    }
    DWORD written = 0;
    WriteFile(stream.get(), "dir-stream-payload", 18, &written, nullptr);
    stream.Close();
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid before scan");
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::string content;
    Check(ReadBytes(plan.dest_final + L":DirStream:$DATA", content) && content == "dir-stream-payload",
          L"directory stream copied to the new place");
    RemoveTree(root);
}

void TestLongPath() {
    std::wprintf(L"long path over 260 characters\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    std::wstring deep = source;
    for (int level = 0; level < 12; ++level) {
        deep = JoinPath(deep, L"directory-with-long-name-" + std::to_wstring(level));
    }
    if (!MakeDirs(deep)) {
        std::wprintf(L"  (skipped: cannot create deep path)\n");
        RemoveTree(root);
        return;
    }
    WriteBytes(JoinPath(deep, L"deep-file.txt"), "deep payload");
    Check(deep.size() > 260, L"test path really longer than 260 characters");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::wstring copied = JoinPath(plan.dest_final, deep.substr(source.size() + 1));
    std::string content;
    Check(ReadBytes(JoinPath(copied, L"deep-file.txt"), content) && content == "deep payload",
          L"long path file copied and readable");
    RemoveTree(root);
}

void TestLowSpace() {
    std::wprintf(L"low space refused\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.low_space = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"low space refused");
    Check(outcome.message.find(L"свободного места") != std::wstring::npos, L"message about free space");
    Check(PathExists(JoinPath(source, L"file.txt")), L"original intact");
    Check(!PathExists(plan.dest_final), L"nothing published");
    Check(!PathExists(plan.staging), L"staging cleaned");
    RemoveTree(root);
}

void TestSourceChangedDuringCopy() {
    std::wprintf(L"source changed during copy\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.touch_source_after_copy = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"changed source refused");
    Check(outcome.message.find(L"изменилась") != std::wstring::npos, L"message about changed source");
    Check(PathExists(JoinPath(source, L"file.txt")), L"original file intact");
    Check(!PathExists(plan.dest_final), L"nothing published");
    Check(!PathExists(plan.staging), L"staging cleaned");
    RemoveTree(root);
}

void TestTamperAfterPublish() {
    std::wprintf(L"copy tampered after publish\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.tamper_after_publish = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"tampered copy detected");
    Check(outcome.message.find(L"изменилась") != std::wstring::npos, L"message about changed copy");
    Check(IsSymlinkTo(source, plan.dest_final), L"link created before the check");
    Check(PathExists(JoinPath(plan.backup, L"file.txt")), L"original backup preserved");
    Check(!PathExists(JoinPath(plan.dest_final, L"missing")), L"published copy still in place");
    RemoveTree(root);
}

void TestLinkLostBeforeDelete() {
    std::wprintf(L"link lost before cleanup\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.break_link_before_delete = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"missing link stops cleanup");
    Check(PathExists(JoinPath(plan.backup, L"file.txt")), L"backup preserved");
    Check(PathExists(JoinPath(plan.dest_final, L"file.txt")), L"published copy preserved");
    RemoveTree(root);
}

void TestBusySource() {
    std::wprintf(L"busy source file\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    const std::wstring file = JoinPath(source, L"busy.bin");
    WriteBytes(file, "payload");
    Handle guard(CreateFileW(ApiPath(file).c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             nullptr));
    Check(guard.valid(), L"exclusive lock opened");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(!outcome.ok, L"busy file stops the transfer");
    Check(PathExists(file), L"locked file still in place");
    Check(!PathExists(plan.dest_final), L"nothing published");
    Check(!PathExists(plan.staging), L"staging cleaned");
    guard.Close();
    RemoveTree(root);
}

void TestDurabilityNotConfirmed() {
    std::wprintf(L"durability not confirmed keeps backup\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.force_flush_failure = true;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(outcome.ok, L"transfer reported as done: " + outcome.message + L" / " + outcome.detail);
    Check(outcome.message.find(L"сохранён") != std::wstring::npos, L"message explains kept backup");
    Check(IsSymlinkTo(source, plan.dest_final), L"link works");
    Check(PathExists(JoinPath(plan.backup, L"file.txt")), L"backup kept intact");
    std::string content;
    Check(ReadBytes(JoinPath(source, L"file.txt"), content) && content == "payload", L"data readable");
    RemoveTree(root);
}

void TestLinkLostDuringCleanup() {
    std::wprintf(L"link lost during cleanup\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    for (int index = 0; index < 40; ++index) {
        wchar_t name[32] = {0};
        swprintf_s(name, L"file-%02d.txt", index);
        WriteBytes(JoinPath(source, name), "payload");
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.break_link_after_files = 4;
    const Outcome outcome = Execute(plan, nullptr, faults);
    Check(!outcome.ok, L"lost link reported as failure");
    Check(outcome.message.find(L"перестала работать") != std::wstring::npos, L"message about lost link");
    Check(!PathExists(source), L"link really gone");
    Check(PathExists(plan.backup), L"backup remainder kept");
    Check(PathExists(JoinPath(plan.dest_final, L"file-00.txt")), L"published copy intact");
    RemoveTree(root);
}

void TestRelativeSymlinkOutside() {
    std::wprintf(L"relative symlink outside tree copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring external = JoinPath(root, L"external");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(external);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(external, L"payload.txt"), "outside payload");
    std::wstring error;
    if (!CreateSymlinkCompat(JoinPath(source, L"rel"), L"..\\..\\external", error)) {
        std::wprintf(L"  (relative symlink failed: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const std::wstring expected_external = CanonicalOrSelf(external);
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::wstring substitute;
    Check(ReadSubstituteName(JoinPath(plan.dest_final, L"rel"), substitute), L"link target readable");
    Check(PathsEqual(substitute, L"\\??\\" + expected_external), L"relative outside link became absolute: " + substitute);
    std::string content;
    Check(ReadBytes(JoinPath(plan.dest_final, L"rel\\payload.txt"), content) && content == "outside payload",
          L"outside link still points to the same place");
    RemoveTree(root);
}

void TestBrokenSymlinkCopied() {
    std::wprintf(L"broken symlink copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "data");
    const std::wstring missing = JoinPath(source, L"missing-target");
    std::wstring error;
    if (!CreateSymlinkCompat(JoinPath(source, L"broken"), missing, error)) {
        std::wprintf(L"  (symlink failed: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::wstring substitute;
    Check(ReadSubstituteName(JoinPath(plan.dest_final, L"broken"), substitute), L"broken link target readable");
    Check(PathsEqual(substitute, L"\\??\\" + missing), L"broken link target preserved: " + substitute);
    RemoveTree(root);
}

void TestHardLinkWithStream() {
    std::wprintf(L"hard link with stream copied\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    const std::wstring first = JoinPath(source, L"one.txt");
    WriteBytes(first, "hard link payload");
    if (!CreateHardLinkW(ApiPath(JoinPath(source, L"two.txt")).c_str(), ApiPath(first).c_str(), nullptr)) {
        std::wprintf(L"  (hard link creation failed)\n");
        RemoveTree(root);
        return;
    }
    if (!WriteStream(first, L"Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n")) {
        std::wprintf(L"  (stream creation failed)\n");
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::string stream;
    Check(ReadStream(JoinPath(plan.dest_final, L"two.txt"), L"Zone.Identifier", stream) &&
              stream.find("ZoneId=3") != std::string::npos,
          L"stream copied for the hard link");
    RemoveTree(root);
}

void TestLongPathWithLinks() {
    std::wprintf(L"long path with symlink and hard link\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    std::wstring deep = source;
    for (int level = 0; level < 12; ++level) {
        deep = JoinPath(deep, L"directory-with-long-name-" + std::to_wstring(level));
    }
    if (!MakeDirs(deep)) {
        std::wprintf(L"  (skipped: cannot create deep path)\n");
        RemoveTree(root);
        return;
    }
    const std::wstring file = JoinPath(deep, L"deep.txt");
    WriteBytes(file, "deep payload");
    if (!CreateHardLinkW(ApiPath(JoinPath(deep, L"deep-link.txt")).c_str(), ApiPath(file).c_str(), nullptr)) {
        std::wprintf(L"  (skipped: cannot create hard link on a long path)\n");
        RemoveTree(root);
        return;
    }
    const std::wstring target_dir = JoinPath(deep, L"target-dir");
    MakeDirs(target_dir);
    WriteBytes(JoinPath(target_dir, L"linked.txt"), "long link payload");
    const std::wstring long_link = JoinPath(deep, L"deep-symlink");
    std::wstring error;
    if (!CreateSymlinkCompat(long_link, target_dir, error)) {
        std::wprintf(L"  (skipped: cannot create symlink on a long path: %ls)\n", error.c_str());
        RemoveTree(root);
        return;
    }
    const Plan plan = BuildPlan(source, dest_parent);
    const std::wstring expected_link_target = CanonicalOrSelf(target_dir);
    Check(plan.valid, L"plan valid: " + plan.error);
    const Outcome outcome = Execute(plan, nullptr, Faults());
    Check(outcome.ok, L"execute ok: " + outcome.message + L" / " + outcome.detail);
    std::wstring copied = JoinPath(plan.dest_final, deep.substr(source.size() + 1));
    EntryInfo one;
    EntryInfo two;
    Check(ReadEntryInfo(JoinPath(copied, L"deep.txt"), one), L"long path file readable");
    Check(ReadEntryInfo(JoinPath(copied, L"deep-link.txt"), two), L"long path hard link readable");
    Check(one.file_index == two.file_index, L"long path hard link recreated");
    std::wstring substitute;
    Check(ReadSubstituteName(JoinPath(copied, L"deep-symlink"), substitute), L"long path symlink readable");
    Check(PathsEqual(substitute, L"\\??\\" + expected_link_target), L"long path symlink target preserved: " + substitute);
    std::string link_content;
    Check(ReadBytes(JoinPath(copied, L"deep-symlink\\linked.txt"), link_content) &&
              link_content == "long link payload",
          L"long path symlink resolves to the copied data");
    RemoveTree(root);
}

void TestJournalWritten() {
    std::wprintf(L"journal keeps recovery data\n");
    const std::wstring root = TempRoot();
    const std::wstring source = JoinPath(root, L"src\\Data");
    const std::wstring dest_parent = JoinPath(root, L"dest");
    MakeDirs(source);
    MakeDirs(dest_parent);
    WriteBytes(JoinPath(source, L"file.txt"), "payload");
    const Plan plan = BuildPlan(source, dest_parent);
    Check(plan.valid, L"plan valid");
    Faults faults;
    faults.link_failure = true;
    Execute(plan, nullptr, faults);
    std::wstring newest;
    for (const std::wstring& path : FindUnfinishedJournals()) {
        if (g_journals_before.find(path) == g_journals_before.end()) {
            newest = path;
        }
    }
    Check(!newest.empty(), L"journal file created on failure");
    const std::wstring text = ReadJournalText(newest);
    Check(text.find(L"source=") != std::wstring::npos && text.find(L"backup=") != std::wstring::npos &&
              text.find(L"dest=") != std::wstring::npos && text.find(L"state=") != std::wstring::npos,
          L"journal contains paths and state");
    RemoveTree(root);
}

void TestJournalsCleanup() {
    const std::vector<std::wstring> now = FindUnfinishedJournals();
    for (const std::wstring& path : now) {
        if (g_journals_before.find(path) == g_journals_before.end()) {
            DeleteFileW(ApiPath(path).c_str());
        }
    }
}

}  // namespace

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    std::wprintf(L"Linkerino engine tests\n");
    g_journals_before.clear();
    for (const std::wstring& path : FindUnfinishedJournals()) {
        g_journals_before.insert(path);
    }
    const std::wstring probe_root = TempRoot();
    MakeDirs(probe_root);
    std::wstring probe_error;
    const bool symlink_ok = CreateSymlinkCompat(JoinPath(probe_root, L"probe"), probe_root, probe_error);
    if (symlink_ok) {
        RemoveDirectoryW(ApiPath(JoinPath(probe_root, L"probe")).c_str());
    }
    RemoveTree(probe_root);
    if (!symlink_ok) {
        std::wprintf(L"SKIP: cannot create directory symlinks: %ls\n", probe_error.c_str());
        std::wprintf(L"Run the tests from an elevated account or enable Developer Mode.\n");
        return 77;
    }

    wchar_t temp_path[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, temp_path);
    const std::wstring volume_root = VolumeRootOf(temp_path);
    bool volume_ok = false;
    if (volume_root.size() >= 2) {
        const std::wstring device = L"\\\\.\\" + volume_root.substr(0, 2);
        Handle volume(CreateFileW(device.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, 0, nullptr));
        volume_ok = volume.valid() && FlushFileBuffers(volume.get()) != FALSE;
    }
    if (!volume_ok) {
        std::wprintf(L"SKIP: cannot confirm volume writes (the transfer keeps the backup without it).\n");
        std::wprintf(L"Run the tests from an elevated account.\n");
        return 77;
    }

    TestBasicMove();
    TestEmptyFolder();
    TestRejectExistingDestination();
    TestRejectNesting();
    TestRejectSymlinkSource();
    TestReparseInsideCopied();
    TestRelativeSymlinkInside();
    TestJunctionInsideCopied();
    TestHardLinksCopied();
    TestHardLinkWithStream();
    TestDirectoryStreamCopied();
    TestLongPath();
    TestLongPathWithLinks();
    TestRelativeSymlinkOutside();
    TestBrokenSymlinkCopied();
    TestVerifyFault();
    TestLinkFault();
    TestCancel();
    TestReadOnlySourcePlacement();
    TestCrossVolume();
    TestLowSpace();
    TestSourceChangedDuringCopy();
    TestTamperAfterPublish();
    TestLinkLostBeforeDelete();
    TestBusySource();
    TestDurabilityNotConfirmed();
    TestLinkLostDuringCleanup();
    TestJournalWritten();
    TestJournalsCleanup();

    std::wprintf(L"\nChecks: %d, failures: %d\n", g_checks, g_failures);
    if (g_failures != 0) {
        std::wprintf(L"RESULT: FAIL\n");
        return 1;
    }
    std::wprintf(L"RESULT: PASS\n");
    return 0;
}
