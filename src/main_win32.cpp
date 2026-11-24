#include "engine.h"
#include "win_util.h"

#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <string>
#include <thread>

using namespace linkerino;

namespace {

constexpr UINT kMsgProgress = WM_APP + 1;
constexpr UINT kMsgDone = WM_APP + 2;
constexpr UINT kMsgJournals = WM_APP + 3;

constexpr int kIdSourceEdit = 1001;
constexpr int kIdSourceBrowse = 1002;
constexpr int kIdDestEdit = 1003;
constexpr int kIdDestBrowse = 1004;
constexpr int kIdStart = 1005;
constexpr int kIdCancel = 1006;
constexpr int kIdProgress = 1007;

HWND g_title = nullptr;
HWND g_source_label = nullptr;
HWND g_source_edit = nullptr;
HWND g_source_browse = nullptr;
HWND g_dest_label = nullptr;
HWND g_dest_edit = nullptr;
HWND g_dest_browse = nullptr;
HWND g_result = nullptr;
HWND g_progress = nullptr;
HWND g_status = nullptr;
HWND g_start = nullptr;
HWND g_cancel = nullptr;
HFONT g_font = nullptr;
HFONT g_title_font = nullptr;
HBRUSH g_background = nullptr;

std::thread g_worker;
std::atomic<bool> g_cancel_requested(false);
bool g_running = false;

class WindowSink : public ProgressSink {
public:
    explicit WindowSink(HWND window) : window_(window) {}

    void OnProgress(const Progress& progress) override {
        auto* copy = new Progress(progress);
        if (!PostMessageW(window_, kMsgProgress, 0, reinterpret_cast<LPARAM>(copy))) {
            delete copy;
        }
    }

    bool CancelRequested() override { return g_cancel_requested.load(); }

private:
    HWND window_;
};

std::wstring GetText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    if (length > 0) {
        GetWindowTextW(control, &text[0], length + 1);
    }
    text.resize(static_cast<std::size_t>(length));
    return text;
}

void SetText(HWND control, const std::wstring& text) {
    SetWindowTextW(control, text.c_str());
}

void SetStatus(const std::wstring& text) {
    SetText(g_status, text);
    UpdateWindow(g_status);
}

void SetProgressPercent(int percent) {
    if (percent < 0) {
        percent = 0;
    }
    if (percent > 100) {
        percent = 100;
    }
    SendMessageW(g_progress, PBM_SETPOS, static_cast<WPARAM>(percent), 0);
}

void UpdateResultPreview() {
    const Plan plan = BuildPlan(GetText(g_source_edit), GetText(g_dest_edit));
    if (plan.valid) {
        SetText(g_result, L"На новом месте появится: " + plan.dest_final +
                              L"\nСтарый путь станет ссылкой на эту папку.");
    } else if (GetText(g_source_edit).empty() || GetText(g_dest_edit).empty()) {
        SetText(g_result, L"Выберите папку для переноса и папку назначения.");
    } else {
        SetText(g_result, L"Проверка: " + plan.error);
    }
}

std::wstring BrowseForFolder(HWND owner) {
    BROWSEINFOW info = {};
    info.hwndOwner = owner;
    info.lpszTitle = L"Выберите папку";
    info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE id_list = SHBrowseForFolderW(&info);
    if (id_list == nullptr) {
        return std::wstring();
    }
    wchar_t path[MAX_PATH] = {0};
    std::wstring result;
    if (SHGetPathFromIDListW(id_list, path)) {
        result = path;
    }
    CoTaskMemFree(id_list);
    return result;
}

void EnableInputs(bool enabled) {
    EnableWindow(g_source_edit, enabled ? TRUE : FALSE);
    EnableWindow(g_source_browse, enabled ? TRUE : FALSE);
    EnableWindow(g_dest_edit, enabled ? TRUE : FALSE);
    EnableWindow(g_dest_browse, enabled ? TRUE : FALSE);
    EnableWindow(g_start, enabled ? TRUE : FALSE);
    EnableWindow(g_cancel, enabled && g_running ? TRUE : FALSE);
}

void RestartElevated(HWND window) {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, &buffer[0], static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            MessageBoxW(window, L"Не удалось определить путь к программе.", L"Перезапуск", MB_OK | MB_ICONWARNING);
            return;
        }
        if (length < buffer.size()) {
            buffer.resize(length);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    const std::wstring directory = ParentPath(buffer);
    const HINSTANCE result =
        ShellExecuteW(window, L"runas", buffer.c_str(), nullptr, directory.empty() ? nullptr : directory.c_str(),
                      SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        MessageBoxW(window, L"Перезапуск от имени администратора не удался. Запустите программу вручную от имени администратора.",
                    L"Перезапуск", MB_OK | MB_ICONWARNING);
        return;
    }
    DestroyWindow(window);
}

void StartTransfer(HWND window) {
    if (g_running) {
        return;
    }
    const Plan plan = BuildPlan(GetText(g_source_edit), GetText(g_dest_edit));
    if (!plan.valid) {
        LogLine(L"plan rejected: " + plan.error);
        MessageBoxW(window, plan.error.c_str(), L"Проверка путей", MB_OK | MB_ICONWARNING);
        return;
    }
    const std::wstring question = L"Перенести папку?\n\n" + plan.source + L"\n  →  " + plan.dest_final +
                                  L"\n\nСначала копия будет сверена, и только потом старый путь станет ссылкой.";
    if (MessageBoxW(window, question.c_str(), L"Подтверждение переноса",
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
        return;
    }
    g_cancel_requested.store(false);
    g_running = true;
    EnableInputs(false);
    EnableWindow(g_cancel, TRUE);
    SetProgressPercent(0);
    SetStatus(L"Начинаю перенос…");
    LogLine(L"GUI start requested");
    g_worker = std::thread([window, plan]() {
        WindowSink sink(window);
        const Outcome outcome = Execute(plan, &sink, Faults());
        auto* copy = new Outcome(outcome);
        if (!PostMessageW(window, kMsgDone, 0, reinterpret_cast<LPARAM>(copy))) {
            delete copy;
        }
    });
}

std::wstring JournalStateText(const std::wstring& path) {
    const std::wstring text = ReadJournalText(path);
    const std::size_t begin = text.find(L"state=");
    if (begin == std::wstring::npos) {
        return std::wstring();
    }
    const std::size_t line_end = text.find(L"\r\n", begin);
    const std::size_t length =
        line_end == std::wstring::npos ? std::wstring::npos : line_end - begin - std::wstring(L"state=").size();
    return text.substr(begin + std::wstring(L"state=").size(), length);
}

void ShowJournals(HWND window) {
    const std::vector<std::wstring> journals = FindUnfinishedJournals();
    if (journals.empty()) {
        return;
    }
    std::wstring text = L"Найдены записи о незавершённых переносах.\n\n"
                        L"Программа ничего не удаляет и не восстанавливает автоматически. "
                        L"Проверьте указанные папки вручную:\n\n";
    for (const std::wstring& path : journals) {
        const std::wstring state = JournalStateText(path);
        text += path;
        if (!state.empty()) {
            text += L"  [" + state + L"]";
        }
        text += L"\n";
    }
    text += L"\nПапка журналов: " + JournalDirectory();
    MessageBoxW(window, text.c_str(), L"Незавершённый перенос", MB_OK | MB_ICONWARNING);
}

void LayoutChildren(HWND window) {
    RECT client = {};
    GetClientRect(window, &client);
    const int width = client.right - client.left;
    const int margin = 16;
    const int edit_width = width - margin * 2 - 110;
    MoveWindow(g_title, margin, 12, width - margin * 2, 24, TRUE);
    MoveWindow(g_source_label, margin, 44, width - margin * 2, 18, TRUE);
    MoveWindow(g_source_edit, margin, 64, edit_width, 26, TRUE);
    MoveWindow(g_source_browse, margin + edit_width + 8, 63, 100, 27, TRUE);
    MoveWindow(g_dest_label, margin, 100, width - margin * 2, 18, TRUE);
    MoveWindow(g_dest_edit, margin, 120, edit_width, 26, TRUE);
    MoveWindow(g_dest_browse, margin + edit_width + 8, 119, 100, 27, TRUE);
    MoveWindow(g_result, margin, 154, width - margin * 2, 44, TRUE);
    MoveWindow(g_progress, margin, 212, width - margin * 2, 20, TRUE);
    MoveWindow(g_status, margin, 238, width - margin * 2, 46, TRUE);
    MoveWindow(g_start, margin, 300, 170, 34, TRUE);
    MoveWindow(g_cancel, margin + 182, 300, 130, 34, TRUE);
}

WNDPROC g_edit_proc = nullptr;

LRESULT CALLBACK EditProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CHAR && (wparam == L'\r' || wparam == L'\n')) {
        SetFocus(g_start);
        return 0;
    }
    return CallWindowProcW(g_edit_proc, window, message, wparam, lparam);
}

void ApplyFont(HWND control, HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
        case WM_CREATE: {
            NONCLIENTMETRICSW metrics = {};
            metrics.cbSize = sizeof(metrics);
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
                g_font = CreateFontIndirectW(&metrics.lfMessageFont);
            }
            if (g_font == nullptr) {
                g_font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            }
            LOGFONTW title_metrics = {};
            if (g_font != nullptr) {
                GetObjectW(g_font, sizeof(title_metrics), &title_metrics);
                title_metrics.lfWeight = FW_SEMIBOLD;
                title_metrics.lfHeight = static_cast<LONG>(title_metrics.lfHeight * 1.35);
                g_title_font = CreateFontIndirectW(&title_metrics);
            }
            g_background = CreateSolidBrush(RGB(250, 250, 252));

            g_title = CreateWindowExW(0, L"STATIC", L"Linkerino — перенести папку и оставить ссылку",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window, nullptr,
                                      GetModuleHandleW(nullptr), nullptr);
            g_source_label = CreateWindowExW(0, L"STATIC", L"Папка, которую нужно перенести:",
                                             WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window, nullptr,
                                             GetModuleHandleW(nullptr), nullptr);
            g_source_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, window,
                                            reinterpret_cast<HMENU>(kIdSourceEdit), GetModuleHandleW(nullptr), nullptr);
            g_source_browse = CreateWindowExW(0, L"BUTTON", L"Выбрать…",
                                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, window,
                                              reinterpret_cast<HMENU>(kIdSourceBrowse), GetModuleHandleW(nullptr),
                                              nullptr);
            g_dest_label = CreateWindowExW(0, L"STATIC", L"Куда перенести (существующая папка):",
                                           WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window, nullptr,
                                           GetModuleHandleW(nullptr), nullptr);
            g_dest_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, window,
                                          reinterpret_cast<HMENU>(kIdDestEdit), GetModuleHandleW(nullptr), nullptr);
            g_dest_browse = CreateWindowExW(0, L"BUTTON", L"Выбрать…",
                                            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, window,
                                            reinterpret_cast<HMENU>(kIdDestBrowse), GetModuleHandleW(nullptr), nullptr);
            g_result = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window,
                                       nullptr, GetModuleHandleW(nullptr), nullptr);
            g_progress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 0, 0, 0, 0,
                                         window, reinterpret_cast<HMENU>(kIdProgress), GetModuleHandleW(nullptr),
                                         nullptr);
            g_status = CreateWindowExW(0, L"STATIC", L"Выберите папки и нажмите «Перенести».",
                                       WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window, nullptr,
                                       GetModuleHandleW(nullptr), nullptr);
            g_start = CreateWindowExW(0, L"BUTTON", L"Перенести",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, window,
                                      reinterpret_cast<HMENU>(kIdStart), GetModuleHandleW(nullptr), nullptr);
            g_cancel = CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                       0, 0, 0, 0, window, reinterpret_cast<HMENU>(kIdCancel), GetModuleHandleW(nullptr),
                                       nullptr);

            HWND controls[] = {g_title, g_source_label, g_source_edit, g_source_browse, g_dest_label,
                               g_dest_edit, g_dest_browse, g_result, g_progress, g_status, g_start, g_cancel};
            for (HWND control : controls) {
                if (control != nullptr) {
                    ApplyFont(control, g_font);
                }
            }
            ApplyFont(g_title, g_title_font != nullptr ? g_title_font : g_font);
            g_edit_proc = reinterpret_cast<WNDPROC>(
                SetWindowLongPtrW(g_source_edit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(EditProc)));
            SetWindowLongPtrW(g_dest_edit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(EditProc));
            SendMessageW(g_progress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            EnableWindow(g_cancel, FALSE);
            LayoutChildren(window);
            UpdateResultPreview();
            PostMessageW(window, kMsgJournals, 0, 0);
            return 0;
        }
        case WM_SIZE:
            LayoutChildren(window);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
            info->ptMinTrackSize.x = 760;
            info->ptMinTrackSize.y = 420;
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetBkColor(dc, RGB(250, 250, 252));
            return reinterpret_cast<LRESULT>(g_background);
        }
        case WM_CTLCOLORBTN: {
            HDC dc = reinterpret_cast<HDC>(wparam);
            SetBkColor(dc, RGB(250, 250, 252));
            return reinterpret_cast<LRESULT>(g_background);
        }
        case WM_COMMAND: {
            const int id = LOWORD(wparam);
            const int code = HIWORD(wparam);
            if (id == kIdSourceBrowse && code == BN_CLICKED) {
                const std::wstring picked = BrowseForFolder(window);
                if (!picked.empty()) {
                    SetText(g_source_edit, picked);
                    UpdateResultPreview();
                }
                return 0;
            }
            if (id == kIdDestBrowse && code == BN_CLICKED) {
                const std::wstring picked = BrowseForFolder(window);
                if (!picked.empty()) {
                    SetText(g_dest_edit, picked);
                    UpdateResultPreview();
                }
                return 0;
            }
            if ((id == kIdSourceEdit || id == kIdDestEdit) && code == EN_CHANGE) {
                if (!g_running) {
                    UpdateResultPreview();
                }
                return 0;
            }
            if (id == kIdStart && code == BN_CLICKED) {
                StartTransfer(window);
                return 0;
            }
            if (id == kIdCancel && code == BN_CLICKED) {
                g_cancel_requested.store(true);
                SetStatus(L"Останавливаюсь после безопасного шага…");
                EnableWindow(g_cancel, FALSE);
                return 0;
            }
            return 0;
        }
        case kMsgProgress: {
            auto* progress = reinterpret_cast<Progress*>(lparam);
            if (progress != nullptr) {
                std::wstring text = PhaseText(progress->phase);
                if (!progress->item.empty()) {
                    text += L": " + progress->item;
                }
                SetStatus(text);
                if (progress->phase == Phase::Publish || progress->phase == Phase::Link ||
                    progress->phase == Phase::Cleanup) {
                    EnableWindow(g_cancel, FALSE);
                }
                int percent = 0;
                if (progress->bytes_total > 0) {
                    percent = static_cast<int>((progress->bytes_done * 100) / progress->bytes_total);
                } else if (progress->files_total > 0) {
                    percent = static_cast<int>((progress->files_done * 100) / progress->files_total);
                }
                SetProgressPercent(percent);
                delete progress;
            }
            return 0;
        }
        case kMsgDone: {
            auto* outcome = reinterpret_cast<Outcome*>(lparam);
            if (g_worker.joinable()) {
                g_worker.join();
            }
            g_running = false;
            EnableInputs(true);
            EnableWindow(g_cancel, FALSE);
            if (outcome != nullptr) {
                std::wstring text = outcome->message;
                if (!outcome->notes.empty()) {
                    text += L"\n\n" + outcome->notes;
                }
                if (!outcome->detail.empty()) {
                    text += L"\n\nПодробности: " + outcome->detail;
                }
                if (!outcome->leftover.empty()) {
                    text += L"\n\nГде лежат данные: " + outcome->leftover;
                }
                const bool ok = outcome->ok;
                const bool offer_restart = outcome->needs_elevation && !ok;
                const std::wstring status = outcome->message;
                MessageBoxW(window, text.c_str(), ok ? L"Готово" : L"Перенос не завершён",
                            MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
                SetStatus(status);
                if (ok) {
                    SetProgressPercent(100);
                }
                delete outcome;
                if (offer_restart) {
                    if (MessageBoxW(window,
                                    L"Для создания ссылки нужны права администратора.\n\n"
                                    L"Перезапустить программу от имени администратора?\n"
                                    L"Перенос сам не начнётся — папки придётся выбрать заново.",
                                    L"Нужны права", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1) == IDYES) {
                        RestartElevated(window);
                    }
                }
            }
            return 0;
        }
        case kMsgJournals:
            ShowJournals(window);
            return 0;
        case WM_CLOSE:
            if (g_running) {
                MessageBoxW(window,
                            L"Перенос ещё идёт. Дождитесь его окончания или нажмите «Отмена» "
                            L"до начала изменения старой папки.",
                            L"Идёт перенос", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    SetProcessDPIAware();
    INITCOMMONCONTROLSEX controls = {};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);
    LogLine(L"Linkerino started, build " + std::to_wstring(WindowsBuildNumber()));

    WNDCLASSEXW window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
    window_class.lpszClassName = L"LinkerinoMainWindow";
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    if (RegisterClassExW(&window_class) == 0) {
        CoUninitialize();
        return 1;
    }

    RECT desired = {0, 0, 740, 360};
    AdjustWindowRect(&desired, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN, FALSE);
    const int width = desired.right - desired.left;
    const int height = desired.bottom - desired.top;
    HWND window = CreateWindowExW(0, window_class.lpszClassName, L"Linkerino", WS_OVERLAPPED | WS_CAPTION |
                                      WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
                                  CW_USEDEFAULT, CW_USEDEFAULT, width, height, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) {
        CoUninitialize();
        return 1;
    }
    ShowWindow(window, show_command);
    UpdateWindow(window);

    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (g_font != nullptr) {
        DeleteObject(g_font);
    }
    if (g_title_font != nullptr) {
        DeleteObject(g_title_font);
    }
    if (g_background != nullptr) {
        DeleteObject(g_background);
    }
    CoUninitialize();
    return static_cast<int>(message.wParam);
}
