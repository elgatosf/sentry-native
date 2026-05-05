#include "sentry_testsupport.h"

#ifdef SENTRY_PLATFORM_WINDOWS

#    include "../../src/wer/sentry_wer_stowed.h"

#    include <cstring>
#    include <string>
#    include <vector>

static void
test_stowed_log(const wchar_t *, ...)
{
}

TEST_VISIBLE void
test_stowed_frame_0(void)
{
}

TEST_VISIBLE void
test_stowed_frame_1(void)
{
}

static std::wstring
make_temp_file_path(void)
{
    wchar_t temp_dir[MAX_PATH];
    DWORD temp_dir_len = GetTempPathW(_countof(temp_dir), temp_dir);
    TEST_ASSERT(temp_dir_len > 0);
    TEST_ASSERT(temp_dir_len < _countof(temp_dir));

    wchar_t temp_path[MAX_PATH];
    UINT temp_name_result = GetTempFileNameW(temp_dir, L"stw", 0, temp_path);
    TEST_ASSERT(temp_name_result != 0);
    DeleteFileW(temp_path);
    return std::wstring(temp_path);
}

static std::string
read_text_file_utf8(const wchar_t *path)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    TEST_ASSERT(file != INVALID_HANDLE_VALUE);

    LARGE_INTEGER size = { };
    TEST_ASSERT(GetFileSizeEx(file, &size));
    TEST_ASSERT(size.HighPart == 0);

    std::vector<char> content((size_t)size.LowPart + 1, '\0');
    DWORD bytes_read = 0;
    TEST_ASSERT(
        ReadFile(file, content.data(), size.LowPart, &bytes_read, nullptr));
    TEST_ASSERT(bytes_read == (DWORD)size.LowPart);
    CloseHandle(file);

    return std::string(content.data(), bytes_read);
}

#endif

extern "C" SENTRY_TEST(wer_stowed_collects_ranges_and_writes_stack_text)
{
#ifdef SENTRY_PLATFORM_WINDOWS
    void *stack_words[] = {
        (void *)&test_stowed_frame_0,
        (void *)&test_stowed_frame_1,
    };

    sentry_stowed_exception_information_v2 stowed = { };
    stowed.header.size = sizeof(stowed);
    stowed.header.signature = SENTRY_WER_STOWED_SIGNATURE_V2;
    stowed.result_code = E_FAIL;
    stowed.form.bits.exception_form = SENTRY_WER_STOWED_FORM_BINARY;
    stowed.form.bits.thread_id = GetCurrentThreadId();
    stowed.payload.binary.exception_address = (PVOID)&test_stowed_frame_0;
    stowed.payload.binary.stack_trace_word_size = sizeof(void *);
    stowed.payload.binary.stack_trace_words = _countof(stack_words);
    stowed.payload.binary.stack_trace = stack_words;

    sentry_stowed_exception_information_v2 nested = { };
    nested.header.size = sizeof(nested);
    nested.header.signature = SENTRY_WER_STOWED_SIGNATURE_V2;
    nested.result_code = E_POINTER;
    nested.form.bits.exception_form = SENTRY_WER_STOWED_FORM_BINARY;
    nested.form.bits.thread_id = GetCurrentThreadId();
    nested.payload.binary.exception_address = (PVOID)&test_stowed_frame_1;
    nested.payload.binary.stack_trace_word_size = sizeof(void *);
    nested.payload.binary.stack_trace_words = _countof(stack_words);
    nested.payload.binary.stack_trace = stack_words;
    stowed.nested_exception_type = SENTRY_WER_STOWED_SIGNATURE_V2;
    stowed.nested_exception = &nested;

    sentry_stowed_exception_information_v2 stowed2 = { };
    stowed2.header.size = sizeof(stowed2);
    stowed2.header.signature = SENTRY_WER_STOWED_SIGNATURE_V2;
    stowed2.result_code = E_INVALIDARG;
    stowed2.form.bits.exception_form = SENTRY_WER_STOWED_FORM_BINARY;
    stowed2.form.bits.thread_id = GetCurrentThreadId();
    stowed2.payload.binary.exception_address = (PVOID)&test_stowed_frame_1;
    stowed2.payload.binary.stack_trace_word_size = sizeof(void *);
    stowed2.payload.binary.stack_trace_words = _countof(stack_words);
    stowed2.payload.binary.stack_trace = stack_words;

    auto leo1_secondary = (ULONG_PTR *)VirtualAlloc(
        nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    auto leo1_message = (ULONG_PTR *)VirtualAlloc(
        nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(leo1_secondary != nullptr);
    TEST_ASSERT(leo1_message != nullptr);

    ULONG_PTR leo1_words[SENTRY_WER_NESTED_PREVIEW_LIMIT / sizeof(ULONG_PTR)]
        = { };
    leo1_secondary[0] = (ULONG_PTR)leo1_message;
    leo1_words[4] = (ULONG_PTR)leo1_secondary;
    leo1_words[31] = (ULONG_PTR)leo1_message;

    stowed2.nested_exception_type = SENTRY_WER_NESTED_TYPE_LEO1;
    stowed2.nested_exception = leo1_words;

    sentry_stowed_exception_information_v2 stowed3 = stowed;
    stowed3.result_code = E_ACCESSDENIED;
    stowed3.nested_exception_type = 0;
    stowed3.nested_exception = nullptr;

    sentry_stowed_exception_information_v2 stowed4 = stowed2;
    stowed4.result_code = E_NOTIMPL;
    stowed4.nested_exception_type = 0;
    stowed4.nested_exception = nullptr;

    ULONG_PTR entry_ptrs[] = {
        (ULONG_PTR)&stowed,
        (ULONG_PTR)&stowed2,
        (ULONG_PTR)&stowed3,
        (ULONG_PTR)&stowed4,
    };

    EXCEPTION_RECORD record = { };
    record.ExceptionCode = STATUS_STOWED_EXCEPTION;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)entry_ptrs;
    record.ExceptionInformation[1] = _countof(entry_ptrs);

    sentry_minidump_memory_range ranges[SENTRY_WER_STOWED_MAX_RANGES] = { };
    std::wstring temp_path = make_temp_file_path();
    char fingerprint[256] = { };

    size_t range_count = sentry_stowed_collect_memory_ranges(test_stowed_log,
        GetCurrentProcess(), record, ranges, _countof(ranges),
        temp_path.c_str(), fingerprint, sizeof(fingerprint));

    TEST_CHECK(range_count >= 4);
    TEST_CHECK(fingerprint[0] != '\0');
    TEST_CHECK(strstr(fingerprint, "stowed1:") != nullptr);
    TEST_CHECK(strstr(fingerprint, "stowed2:") != nullptr);
    TEST_CHECK(strstr(fingerprint, "+0x") == nullptr);
    TEST_CHECK(
        GetFileAttributesW(temp_path.c_str()) != INVALID_FILE_ATTRIBUTES);

    bool found_pointer_array = false;
    bool found_leo1_secondary = false;
    bool found_leo1_message = false;
    for (const auto &range : ranges) {
        if (range.base == (ULONG64)(ULONG_PTR)entry_ptrs
            && range.size >= sizeof(entry_ptrs)) {
            found_pointer_array = true;
        }
        if (range.base == (ULONG64)(ULONG_PTR)leo1_secondary) {
            found_leo1_secondary = true;
        }
        if (range.base == (ULONG64)(ULONG_PTR)leo1_message) {
            found_leo1_message = true;
        }
    }
    TEST_CHECK(found_pointer_array);
    TEST_CHECK(found_leo1_secondary);
    TEST_CHECK(found_leo1_message);

    std::string stack_text = read_text_file_utf8(temp_path.c_str());
    TEST_CHECK(stack_text.find("Entries captured: 2") != std::string::npos);
    TEST_CHECK(stack_text.find("Stowed Exception #1") != std::string::npos);
    TEST_CHECK(stack_text.find("Stowed Exception #2") != std::string::npos);
    TEST_CHECK(stack_text.find("Stowed Exception #3") == std::string::npos);
    TEST_CHECK(stack_text.find("Nested stowed exception") != std::string::npos);
    TEST_CHECK(
        stack_text.find("Associated CLR exception") != std::string::npos);
    TEST_CHECK(stack_text.find("CLR stack hint address") != std::string::npos);
    TEST_CHECK(stack_text.find("Suggested fingerprint") != std::string::npos);
    TEST_CHECK(stack_text.find("#00 ") != std::string::npos);
    TEST_CHECK(stack_text.find("#01 ") != std::string::npos);
    TEST_CHECK(stack_text.find("#-- end --") != std::string::npos);

    DeleteFileW(temp_path.c_str());
    VirtualFree(leo1_message, 0, MEM_RELEASE);
    VirtualFree(leo1_secondary, 0, MEM_RELEASE);
#else
    SKIP_TEST();
#endif
}
