#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace linkerino {

enum class Phase { Validate, Scan, Copy, Verify, Publish, Link, Cleanup, Done, Failed, Cancelled };

const wchar_t* PhaseText(Phase phase);

struct Progress {
    Phase phase = Phase::Validate;
    std::uint64_t bytes_done = 0;
    std::uint64_t bytes_total = 0;
    std::uint64_t files_done = 0;
    std::uint64_t files_total = 0;
    std::wstring item;
};

class ProgressSink {
public:
    virtual ~ProgressSink() = default;
    virtual void OnProgress(const Progress& progress) = 0;
    virtual bool CancelRequested() = 0;
};

struct Plan {
    bool valid = false;
    std::wstring error;
    std::wstring source;
    std::wstring source_parent;
    std::wstring name;
    std::wstring dest_parent;
    std::wstring dest_final;
    std::wstring staging;
    std::wstring backup;
};

struct Faults {
    bool copy_failure = false;
    bool verify_mismatch = false;
    bool link_failure = false;
    bool low_space = false;
    bool touch_source_after_copy = false;
    bool tamper_after_publish = false;
    bool break_link_before_delete = false;
    bool force_flush_failure = false;
    int break_link_after_files = 0;
};

struct Outcome {
    bool ok = false;
    bool cancelled = false;
    bool needs_elevation = false;
    std::wstring message;
    std::wstring detail;
    std::wstring leftover;
    std::wstring dest_final;
};

Plan BuildPlan(const std::wstring& source_input, const std::wstring& dest_parent_input);
Outcome Execute(const Plan& plan, ProgressSink* sink, const Faults& faults);
std::vector<std::wstring> FindUnfinishedJournals();
std::wstring ReadJournalText(const std::wstring& path);

}  // namespace linkerino
