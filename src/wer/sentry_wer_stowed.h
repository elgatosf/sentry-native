#pragma once

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>

#ifndef PSAPI_VERSION
#    define PSAPI_VERSION 2
#endif
#include <psapi.h>

#ifndef _countof
#    define _countof(array) (sizeof(array) / sizeof((array)[0]))
#endif

constexpr size_t SENTRY_WER_STOWED_MAX_POINTERS = 2;
constexpr size_t SENTRY_WER_STOWED_MAX_POINTER_ARRAY_ENTRIES = 64;
constexpr size_t SENTRY_WER_STOWED_MAX_RANGES = 24;
constexpr SIZE_T SENTRY_WER_STOWED_COPY_LIMIT
    = 64 * 1024; // cap per-region ReadProcessMemory to avoid large allocations
constexpr SIZE_T SENTRY_WER_EXCEPTION_ADDR_LIMIT
    = 512; // enough for the HRESULT+context at the exception address
constexpr SIZE_T SENTRY_WER_ERROR_TEXT_LIMIT = 32 * 1024;
constexpr SIZE_T SENTRY_WER_NESTED_PREVIEW_LIMIT = 256;
constexpr size_t SENTRY_WER_STOWED_MAX_NESTING_DEPTH = 3;
// 'SE01' / 'SE02' — the two known signature values that identify a valid
// stowed-exception blob.
constexpr ULONG SENTRY_WER_STOWED_SIGNATURE_V1 = 'SE01';
constexpr ULONG SENTRY_WER_STOWED_SIGNATURE_V2 = 'SE02';
constexpr DWORD SENTRY_WER_STOWED_FORM_BINARY = 0x1;
constexpr DWORD SENTRY_WER_STOWED_FORM_TEXT = 0x2;
constexpr ULONG SENTRY_WER_NESTED_TYPE_LEO1 = 0x314F454C;
constexpr ULONG SENTRY_WER_NESTED_TYPE_XAML = 0x4C4D4158;

#ifndef STATUS_STOWED_EXCEPTION
#    define STATUS_STOWED_EXCEPTION ((DWORD)0xC000027B)
#endif

// The following structs mirror undocumented WinRT / WER internal data layouts
// for stowed exceptions (0xC000027B). They are read from the crashing process
// via ReadProcessMemory and must match the in-memory layout exactly.
struct sentry_stowed_exception_information_header {
    ULONG size;
    ULONG signature;
};

struct sentry_stowed_exception_information_v2 {
    sentry_stowed_exception_information_header header;
    HRESULT result_code;
    union {
        struct {
            DWORD exception_form : 2;
            DWORD thread_id : 30;
        } bits;
        DWORD form_and_thread;
    } form;
    union {
        struct {
            PVOID exception_address;
            ULONG stack_trace_word_size;
            ULONG stack_trace_words;
            PVOID stack_trace;
        } binary;
        struct {
            PWSTR error_text;
        } text;
    } payload;
    ULONG nested_exception_type;
    PVOID nested_exception;
};

struct sentry_stowed_pointer_array {
    ULONG_PTR base;
    ULONG count;
};

struct sentry_minidump_memory_range {
    ULONG64 base;
    ULONG size;
};

inline bool
is_stowed_exception_code(DWORD code)
{
    return code == STATUS_STOWED_EXCEPTION;
}

using sentry_stowed_log_fn = void (*)(const wchar_t *, ...);

class sentry_unique_handle {
public:
    sentry_unique_handle() = default;
    explicit sentry_unique_handle(HANDLE handle)
        : handle_(handle)
    {
    }

    ~sentry_unique_handle() { reset(); }

    sentry_unique_handle(const sentry_unique_handle &) = delete;
    sentry_unique_handle &operator=(const sentry_unique_handle &) = delete;

    sentry_unique_handle(sentry_unique_handle &&other) noexcept
        : handle_(other.release())
    {
    }

    sentry_unique_handle &
    operator=(sentry_unique_handle &&other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    bool
    valid() const
    {
        return handle_ && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE
    get() const { return handle_; }

    void
    reset(HANDLE handle = INVALID_HANDLE_VALUE)
    {
        if (valid()) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

    HANDLE
    release()
    {
        HANDLE handle = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return handle;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

bool sentry_stowed_load_pointer_array(
    const EXCEPTION_RECORD &record, sentry_stowed_pointer_array *out);

bool sentry_stowed_describe_remote_range(HANDLE process, ULONG_PTR address,
    SIZE_T limit, sentry_minidump_memory_range *range);

bool sentry_stowed_append_memory_range(sentry_minidump_memory_range *ranges,
    size_t *count, size_t max_ranges,
    const sentry_minidump_memory_range *candidate);

bool sentry_stowed_write_stack_text(const wchar_t *path, HANDLE process,
    const sentry_stowed_exception_information_v2 &info);

bool sentry_stowed_read_exception(HANDLE process, ULONG_PTR address,
    sentry_stowed_exception_information_v2 *out, sentry_stowed_log_fn log_fn);

bool sentry_stowed_add_pointer_range_if_valid(HANDLE process, ULONG_PTR address,
    SIZE_T limit, sentry_minidump_memory_range *ranges, size_t *count,
    size_t max_ranges, sentry_stowed_log_fn log_fn);

size_t sentry_stowed_collect_memory_ranges(sentry_stowed_log_fn log_fn,
    HANDLE process, const EXCEPTION_RECORD &record,
    sentry_minidump_memory_range *ranges, size_t max_ranges,
    const wchar_t *stack_text_path, char *fingerprint = nullptr,
    size_t fingerprint_len = 0);
