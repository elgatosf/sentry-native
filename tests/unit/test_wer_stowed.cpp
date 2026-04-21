#include "sentry_testsupport.h"

#ifdef SENTRY_PLATFORM_WINDOWS

#    include "../../src/wer/sentry_wer_stowed.h"

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

    ULONG_PTR entry_ptrs[] = {
        (ULONG_PTR)&stowed,
    };

    EXCEPTION_RECORD record = { };
    record.ExceptionCode = STATUS_STOWED_EXCEPTION;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)entry_ptrs;
    record.ExceptionInformation[1] = _countof(entry_ptrs);

    WER_RUNTIME_EXCEPTION_INFORMATION info = { };
    info.hProcess = GetCurrentProcess();
    info.exceptionRecord = record;

    sentry_minidump_memory_range ranges[SENTRY_WER_STOWED_MAX_RANGES] = { };
    std::wstring temp_path = make_temp_file_path();

    size_t range_count = sentry_stowed_collect_memory_ranges(
        test_stowed_log, &info, ranges, _countof(ranges), temp_path.c_str());

    TEST_CHECK(range_count >= 3);
    TEST_CHECK(
        GetFileAttributesW(temp_path.c_str()) != INVALID_FILE_ATTRIBUTES);

    std::string stack_text = read_text_file_utf8(temp_path.c_str());
    TEST_CHECK(stack_text.find("#00 ") != std::string::npos);
    TEST_CHECK(stack_text.find("#01 ") != std::string::npos);
    TEST_CHECK(stack_text.find("#-- end --") != std::string::npos);

    DeleteFileW(temp_path.c_str());
#else
    SKIP_TEST();
#endif
}
