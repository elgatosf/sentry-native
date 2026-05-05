#include "sentry_boot.h"

#include "wer/sentry_wer_long_path.h"
#include "wer/sentry_wer_winhttp.h"

extern "C" {
#include "sentry_alloc.h"
#include "sentry_string.h"
#include "sentry_utils.h"
#include "wer/sentry_wer_common.h"
}

#include <array>
#include <cstring>
#include <dbghelp.h>
#include <new>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <werapi.h>
#include <windows.h>

#include "wer/sentry_wer_stowed.h"

#ifndef _countof
#    define _countof(array) (sizeof(array) / sizeof((array)[0]))
#endif

struct sentry_wer_state {
    std::wstring run_path;
    std::wstring database_path;
    std::string stowed_fingerprint;
};

struct wer_attachment_entry {
    std::wstring path;
    std::string filename;
    std::string content_type;
};

static sentry_wer_state g_state = { };
static constexpr bool SENTRY_WER_ENABLE_STOWED_EXCEPTIONS = true;

enum wer_status {
    WER_STATUS_OK = 0,
    WER_STATUS_CONTEXT_READ_FAIL,
    WER_STATUS_NO_MINIDUMP_URL,
    WER_STATUS_CONSENT_REQUIRED,
    WER_STATUS_DUMP_WRITE_FAIL,
    WER_STATUS_UPLOAD_FAIL,
};

static HRESULT
status_to_hresult(wer_status status)
{
    switch (status) {
    case WER_STATUS_OK:
        return S_OK;
    case WER_STATUS_CONTEXT_READ_FAIL:
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    case WER_STATUS_NO_MINIDUMP_URL:
        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    case WER_STATUS_CONSENT_REQUIRED:
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    case WER_STATUS_DUMP_WRITE_FAIL:
        return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
    case WER_STATUS_UPLOAD_FAIL:
    default:
        return HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED);
    }
}

static void
log_line(const wchar_t *fmt, ...)
{
    wchar_t buf[640];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    size_t len = wcslen(buf);
    if (len + 2 < _countof(buf)) {
        buf[len++] = L'\r';
        buf[len++] = L'\n';
        buf[len] = 0;
    }
    OutputDebugStringW(buf);
}

static const wchar_t *
status_to_name(wer_status status)
{
    switch (status) {
    case WER_STATUS_OK:
        return L"ok";
    case WER_STATUS_CONTEXT_READ_FAIL:
        return L"context-read-fail";
    case WER_STATUS_NO_MINIDUMP_URL:
        return L"no-minidump-url";
    case WER_STATUS_CONSENT_REQUIRED:
        return L"consent-required";
    case WER_STATUS_DUMP_WRITE_FAIL:
        return L"dump-write-fail";
    case WER_STATUS_UPLOAD_FAIL:
    default:
        return L"upload-fail";
    }
}

static const wchar_t *
bool_to_wide(bool value)
{
    return value ? L"yes" : L"no";
}

static HRESULT
log_and_status_to_hresult(wer_status status)
{
    HRESULT hr = status_to_hresult(status);
    log_line(L"Callback exit status=%s hresult=0x%08lX", status_to_name(status),
        (unsigned long)hr);
    return hr;
}

struct sentry_minidump_callback_ctx {
    const sentry_minidump_memory_range *ranges;
    size_t range_count;
    size_t next_index;
};

static BOOL CALLBACK
sentry_minidump_callback(PVOID ctx,
    const PMINIDUMP_CALLBACK_INPUT callback_input,
    PMINIDUMP_CALLBACK_OUTPUT callback_output)
{
    if (!ctx || !callback_input || !callback_output) {
        return FALSE;
    }

    sentry_minidump_callback_ctx *cb_ctx = (sentry_minidump_callback_ctx *)ctx;
    switch (callback_input->CallbackType) {
    case MemoryCallback:
        // Called repeatedly by MiniDumpWriteDump to enumerate extra memory
        // ranges. Return FALSE (with no output) to signal the end of the list.
        if (!cb_ctx->ranges || cb_ctx->next_index >= cb_ctx->range_count) {
            return FALSE;
        }
        callback_output->MemoryBase = cb_ctx->ranges[cb_ctx->next_index].base;
        callback_output->MemorySize = cb_ctx->ranges[cb_ctx->next_index].size;
        cb_ctx->next_index++;
        return TRUE;
    case CancelCallback:
        callback_output->CheckCancel = FALSE;
        callback_output->Cancel = FALSE;
        return TRUE;
    case IncludeThreadCallback:
    case ThreadCallback:
    case ThreadExCallback:
    case IncludeModuleCallback:
    case ModuleCallback:
        return TRUE;
    default:
        return TRUE;
    }
}

static bool
build_path_file(
    const std::wstring &base, const wchar_t *fname, std::wstring *dst)
{
    if (!dst) {
        return false;
    }

    *dst = sentry_wer_join_path(base, fname);
    if (dst->empty()) {
        return false;
    }
    return true;
}

static bool
read_file(const wchar_t *path, BYTE **data, DWORD *len)
{
    *data = nullptr;
    *len = 0;

    std::wstring file_path = sentry_wer_to_extended_path(path);
    if (file_path.empty()) {
        return false;
    }

    HANDLE h = CreateFileW(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size = { };
    if (!GetFileSizeEx(h, &size) || size.HighPart || !size.LowPart) {
        CloseHandle(h);
        return false;
    }

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size.LowPart);
    if (!buf) {
        CloseHandle(h);
        return false;
    }

    DWORD bytes_read = 0;
    if (!ReadFile(h, buf, size.LowPart, &bytes_read, nullptr)
        || bytes_read != (DWORD)size.LowPart) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return false;
    }

    CloseHandle(h);
    *data = buf;
    *len = bytes_read;
    return true;
}

static bool
write_file(const wchar_t *path, const BYTE *data, DWORD len)
{
    if (!path || !data || !len) {
        return false;
    }

    std::wstring file_path = sentry_wer_to_extended_path(path);
    if (file_path.empty()) {
        return false;
    }

    HANDLE h = CreateFileW(file_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    bool ok = WriteFile(h, data, len, &written, nullptr) && written == len;
    CloseHandle(h);
    return ok;
}

static bool
buffer_contains_ascii(const BYTE *data, DWORD len, const char *needle)
{
    if (!data || !needle || !needle[0]) {
        return false;
    }

    size_t needle_len = strlen(needle);
    if (!needle_len || needle_len > len) {
        return false;
    }

    for (DWORD i = 0; i <= len - needle_len; ++i) {
        if (memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static void
append_msgpack_string(std::vector<BYTE> *buffer, const char *value)
{
    size_t len = value ? strlen(value) : 0;
    if (len <= 31) {
        buffer->push_back((BYTE)(0xA0 | len));
    } else if (len <= 0xFF) {
        buffer->push_back(0xD9);
        buffer->push_back((BYTE)len);
    } else {
        buffer->push_back(0xDA);
        buffer->push_back((BYTE)((len >> 8) & 0xFF));
        buffer->push_back((BYTE)(len & 0xFF));
    }
    buffer->insert(buffer->end(), value, value + len);
}

static bool
read_msgpack_map_header(
    const BYTE *data, DWORD len, DWORD *count, DWORD *header_len)
{
    if (!data || !len || !count || !header_len) {
        return false;
    }

    BYTE marker = data[0];
    if ((marker & 0xF0) == 0x80) {
        *count = marker & 0x0F;
        *header_len = 1;
        return true;
    }
    if (marker == 0xDE && len >= 3) {
        *count = ((DWORD)data[1] << 8) | data[2];
        *header_len = 3;
        return true;
    }
    if (marker == 0xDF && len >= 5) {
        *count = ((DWORD)data[1] << 24) | ((DWORD)data[2] << 16)
            | ((DWORD)data[3] << 8) | data[4];
        *header_len = 5;
        return true;
    }
    return false;
}

static void
append_msgpack_map_header(std::vector<BYTE> *buffer, DWORD count)
{
    if (count <= 15) {
        buffer->push_back((BYTE)(0x80 | count));
    } else if (count <= 0xFFFF) {
        buffer->push_back(0xDE);
        buffer->push_back((BYTE)((count >> 8) & 0xFF));
        buffer->push_back((BYTE)(count & 0xFF));
    } else {
        buffer->push_back(0xDF);
        buffer->push_back((BYTE)((count >> 24) & 0xFF));
        buffer->push_back((BYTE)((count >> 16) & 0xFF));
        buffer->push_back((BYTE)((count >> 8) & 0xFF));
        buffer->push_back((BYTE)(count & 0xFF));
    }
}

static bool
patch_event_msgpack_with_stowed_fingerprint(
    BYTE **data, DWORD *len, const std::string &fingerprint)
{
    if (!data || !*data || !len || !*len || fingerprint.empty()) {
        return false;
    }
    if (buffer_contains_ascii(*data, *len, "fingerprint")) {
        return false;
    }

    DWORD map_count = 0;
    DWORD header_len = 0;
    if (!read_msgpack_map_header(*data, *len, &map_count, &header_len)
        || map_count == 0xFFFFFFFF) {
        return false;
    }

    std::vector<BYTE> prefix;
    append_msgpack_map_header(&prefix, map_count + 1);

    std::vector<BYTE> suffix;
    append_msgpack_string(&suffix, "fingerprint");
    suffix.push_back(0x93);
    append_msgpack_string(&suffix, "{{ default }}");
    append_msgpack_string(&suffix, "winrt-stowed");
    append_msgpack_string(&suffix, fingerprint.c_str());

    size_t new_len = prefix.size() + (*len - header_len) + suffix.size();
    if (new_len > MAXDWORD) {
        return false;
    }

    BYTE *patched = (BYTE *)HeapAlloc(GetProcessHeap(), 0, new_len);
    if (!patched) {
        return false;
    }

    BYTE *cursor = patched;
    memcpy(cursor, prefix.data(), prefix.size());
    cursor += prefix.size();
    memcpy(cursor, *data + header_len, *len - header_len);
    cursor += *len - header_len;
    memcpy(cursor, suffix.data(), suffix.size());

    HeapFree(GetProcessHeap(), 0, *data);
    *data = patched;
    *len = (DWORD)new_len;
    return true;
}

static bool
file_exists(const wchar_t *path)
{
    std::wstring file_path = sentry_wer_to_extended_path(path);
    if (file_path.empty()) {
        return false;
    }

    DWORD attrs = GetFileAttributesW(file_path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES
        && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static bool
delete_file_if_exists(const wchar_t *path)
{
    std::wstring file_path = sentry_wer_to_extended_path(path);
    if (file_path.empty()) {
        return false;
    }

    return DeleteFileW(file_path.c_str()) != 0
        || GetLastError() == ERROR_FILE_NOT_FOUND;
}

static bool
read_cstring_field(
    const BYTE *data, size_t len, size_t *offset, std::string *out)
{
    if (!data || !offset || !out || *offset > len) {
        return false;
    }

    size_t start = *offset;
    while (*offset < len && data[*offset] != 0) {
        (*offset)++;
    }
    if (*offset >= len) {
        return false;
    }

    out->assign(reinterpret_cast<const char *>(data + start), *offset - start);
    (*offset)++;
    return true;
}

static std::wstring
utf8_to_wide(const std::string &value)
{
    if (value.empty()) {
        return std::wstring();
    }

    int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (size <= 1) {
        return std::wstring();
    }

    std::wstring result(size - 1, L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), size)
        == 0) {
        return std::wstring();
    }

    return result;
}

static std::vector<wer_attachment_entry>
read_attachment_entries(void)
{
    std::vector<wer_attachment_entry> attachments;

    std::wstring attachments_path;
    if (!build_path_file(
            g_state.run_path, SENTRY_WER_ATTACHMENTS_FILE_W, &attachments_path)
        || !file_exists(attachments_path.c_str())) {
        return attachments;
    }

    BYTE *data = nullptr;
    DWORD len = 0;
    if (!read_file(attachments_path.c_str(), &data, &len) || !len) {
        return attachments;
    }

    size_t offset = 0;
    while (offset < len) {
        std::string path_utf8;
        std::string filename;
        std::string content_type;

        if (!read_cstring_field(data, len, &offset, &path_utf8)
            || !read_cstring_field(data, len, &offset, &filename)
            || !read_cstring_field(data, len, &offset, &content_type)) {
            break;
        }

        std::wstring path_w = utf8_to_wide(path_utf8);
        if (!path_w.empty() && !filename.empty()) {
            attachments.push_back({ std::move(path_w), std::move(filename),
                std::move(content_type) });
        }
    }

    HeapFree(GetProcessHeap(), 0, data);
    return attachments;
}

static bool
has_user_consent(const sentry_wer_runtime_context *ctx)
{
    if (!ctx || !(ctx->flags & SENTRY_WER_FLAG_REQUIRE_CONSENT)) {
        return true;
    }

    std::wstring consent_path;
    if (!build_path_file(
            g_state.database_path, L"user-consent", &consent_path)) {
        return false;
    }

    BYTE *data = nullptr;
    DWORD len = 0;
    if (!read_file(consent_path.c_str(), &data, &len) || !len) {
        return false;
    }

    bool has_consent = data[0] == '1';
    HeapFree(GetProcessHeap(), 0, data);
    return has_consent;
}

static void
write_crash_marker(void)
{
    if (g_state.database_path.empty()) {
        return;
    }

    std::wstring marker_path;
    if (!build_path_file(g_state.database_path, SENTRY_WER_LAST_CRASH_FILE_W,
            &marker_path)) {
        return;
    }

    // Convert FILETIME (100-ns intervals since 1601-01-01) to Unix
    // microseconds.
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ull = { };
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    unsigned long long usec = (ull.QuadPart - 116444736000000000ULL) / 10ULL;

    SYSTEMTIME st;
    GetSystemTime(&st);
    unsigned micros = (unsigned)(usec % 1000000ULL);

    char buf[64];
    int len = _snprintf_s(buf, _countof(buf), _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%06uZ", st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, micros);
    if (len <= 0) {
        return;
    }

    std::wstring marker_file_path
        = sentry_wer_to_extended_path(marker_path.c_str());
    if (marker_file_path.empty()) {
        return;
    }

    HANDLE h = CreateFileW(marker_file_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written = 0;
    WriteFile(h, buf, (DWORD)len, &written, nullptr);
    CloseHandle(h);
}

static void
write_uploaded_marker(void)
{
    if (g_state.run_path.empty()) {
        return;
    }

    std::wstring marker_path;
    if (!build_path_file(g_state.run_path, SENTRY_WER_UPLOADED_MARKER_FILE_W,
            &marker_path)) {
        return;
    }

    static const BYTE uploaded_marker[] = "1";
    if (!write_file(marker_path.c_str(), uploaded_marker,
            (DWORD)(sizeof(uploaded_marker) - 1))) {
        log_line(L"Failed to write upload marker for run \"%s\"",
            g_state.run_path.c_str());
    }
}

static bool
write_minidump(
    const PWER_RUNTIME_EXCEPTION_INFORMATION info, std::wstring *path_out)
{
    if (!info || !path_out || g_state.run_path.empty()) {
        return false;
    }

    if (!build_path_file(
            g_state.run_path, SENTRY_WER_MINIDUMP_FILE_W, path_out)) {
        return false;
    }

    std::wstring dump_file_path
        = sentry_wer_to_extended_path(path_out->c_str());
    if (dump_file_path.empty()) {
        return false;
    }

    log_line(L"Writing minidump target_pid=%lu target_tid=%lu path=\"%s\"",
        info->hProcess ? GetProcessId(info->hProcess) : 0,
        info->hThread ? GetThreadId(info->hThread) : 0, path_out->c_str());

    HANDLE h = CreateFileW(dump_file_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        log_line(L"CreateFile failed err=%lu", GetLastError());
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei = { };
    mei.ThreadId = GetThreadId(info->hThread);
    mei.ClientPointers = FALSE;

    EXCEPTION_POINTERS exc_ptrs = { };
    exc_ptrs.ExceptionRecord
        = const_cast<PEXCEPTION_RECORD>(&info->exceptionRecord);
    exc_ptrs.ContextRecord = const_cast<PCONTEXT>(&info->context);
    mei.ExceptionPointers = &exc_ptrs;

    std::array<sentry_minidump_memory_range, SENTRY_WER_STOWED_MAX_RANGES>
        ranges = { };
    std::wstring stack_path;
    const wchar_t *stack_path_ptr = nullptr;
    if (!g_state.run_path.empty()
        && build_path_file(
            g_state.run_path, SENTRY_WER_STOWED_STACK_FILE_W, &stack_path)) {
        delete_file_if_exists(stack_path.c_str());
        stack_path_ptr = stack_path.c_str();
    }

    char stowed_fingerprint[256] = { };
    size_t range_count = sentry_stowed_collect_memory_ranges(log_line,
        info->hProcess, info->exceptionRecord, ranges.data(), ranges.size(),
        stack_path_ptr, stowed_fingerprint, sizeof(stowed_fingerprint));
    g_state.stowed_fingerprint = stowed_fingerprint;
    sentry_minidump_callback_ctx cb_ctx = { };
    MINIDUMP_CALLBACK_INFORMATION cb_info = { };
    PMINIDUMP_CALLBACK_INFORMATION cb_info_ptr = nullptr;
    if (range_count) {
        cb_ctx.ranges = ranges.data();
        cb_ctx.range_count = range_count;
        cb_ctx.next_index = 0;
        cb_info.CallbackRoutine = sentry_minidump_callback;
        cb_info.CallbackParam = &cb_ctx;
        cb_info_ptr = &cb_info;
        log_line(L"Adding %Iu stowed memory ranges to minidump", range_count);
    }

    // MiniDumpWithIndirectlyReferencedMemory keeps relatively small dumps while
    // preserving stowed exceptions and its references
    MINIDUMP_TYPE dump_type
        = static_cast<MINIDUMP_TYPE>(MiniDumpWithIndirectlyReferencedMemory);
    BOOL ok = MiniDumpWriteDump(info->hProcess, GetProcessId(info->hProcess), h,
        dump_type, &mei, nullptr, cb_info_ptr);
    CloseHandle(h);

    if (!ok) {
        log_line(L"MiniDumpWriteDump failed err=%lu", GetLastError());
        delete_file_if_exists(path_out->c_str());
        return false;
    }

    log_line(L"Minidump written path=\"%s\" stowed_ranges=%Iu",
        path_out->c_str(), range_count);

    return true;
}

static int
append_part_fn(sentry_stringbuilder_t *sb, const char *boundary,
    const char *name, const char *filename, const BYTE *data, size_t len,
    bool add_crlf, const char *content_type)
{
    if (!content_type || !content_type[0]) {
        content_type = "application/octet-stream";
    }

    char head[512];
    int written = snprintf(head, sizeof(head),
        "--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
        "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n",
        boundary, name, filename, content_type);
    if (written < 0 || (size_t)written >= sizeof(head)
        || sentry__stringbuilder_append(sb, head)) {
        return 1;
    }

    char *dst = sentry__stringbuilder_reserve(sb, len + (add_crlf ? 2 : 1));
    if (!dst) {
        return 1;
    }
    memcpy(dst, data, len);
    sb->len += len;

    if (add_crlf) {
        dst = sb->buf + sb->len;
        dst[0] = '\r';
        dst[1] = '\n';
        sb->len += 2;
    }
    sb->buf[sb->len] = '\0';
    return 0;
}

static bool
upload_dump(
    const sentry_wer_runtime_context *ctx, const std::wstring &dump_file_path)
{
    if (!ctx || !ctx->minidump_url[0]) {
        return false;
    }

    URL_COMPONENTSW url = { };
    wchar_t host_buf[260];
    wchar_t path_buf[1024];
    url.dwStructSize = sizeof(url);
    url.lpszHostName = host_buf;
    url.dwHostNameLength = _countof(host_buf);
    url.lpszUrlPath = path_buf;
    url.dwUrlPathLength = _countof(path_buf);
    url.dwSchemeLength = 1;
    if (!WinHttpCrackUrl(ctx->minidump_url, 0, 0, &url)) {
        log_line(L"WinHttpCrackUrl failed gle=%lu", GetLastError());
        return false;
    }

    host_buf[MIN(url.dwHostNameLength, _countof(host_buf) - 1)] = 0;
    path_buf[MIN(url.dwUrlPathLength, _countof(path_buf) - 1)] = 0;

    BYTE *dump_data = nullptr;
    DWORD dump_len = 0;
    if (!read_file(dump_file_path.c_str(), &dump_data, &dump_len)) {
        log_line(L"Failed to read minidump \"%s\"", dump_file_path.c_str());
        return false;
    }

    std::wstring event_path;
    std::wstring bc1_path;
    std::wstring bc2_path;
    std::wstring stowed_stack_path;

    BYTE *event_data = nullptr;
    DWORD event_len = 0;
    BYTE *bc1_data = nullptr;
    DWORD bc1_len = 0;
    BYTE *bc2_data = nullptr;
    DWORD bc2_len = 0;
    BYTE *stowed_stack_data = nullptr;
    DWORD stowed_stack_len = 0;

    bool have_event = build_path_file(g_state.run_path, SENTRY_WER_EVENT_FILE_W,
                          &event_path)
        && file_exists(event_path.c_str())
        && read_file(event_path.c_str(), &event_data, &event_len) && event_len;
    bool have_bc1 = build_path_file(g_state.run_path,
                        SENTRY_WER_BREADCRUMB1_FILE_W, &bc1_path)
        && file_exists(bc1_path.c_str())
        && read_file(bc1_path.c_str(), &bc1_data, &bc1_len) && bc1_len;
    bool have_bc2 = build_path_file(g_state.run_path,
                        SENTRY_WER_BREADCRUMB2_FILE_W, &bc2_path)
        && file_exists(bc2_path.c_str())
        && read_file(bc2_path.c_str(), &bc2_data, &bc2_len) && bc2_len;
    bool have_stowed_stack
        = build_path_file(g_state.run_path, SENTRY_WER_STOWED_STACK_FILE_W,
              &stowed_stack_path)
        && file_exists(stowed_stack_path.c_str())
        && read_file(
            stowed_stack_path.c_str(), &stowed_stack_data, &stowed_stack_len)
        && stowed_stack_len;
    if (have_event
        && patch_event_msgpack_with_stowed_fingerprint(
            &event_data, &event_len, g_state.stowed_fingerprint)) {
        write_file(event_path.c_str(), event_data, event_len);
        log_line(L"Patched staged event with stowed fingerprint");
    }
    std::vector<wer_attachment_entry> attachments = read_attachment_entries();

    INTERNET_PORT port = url.nPort
        ? url.nPort
        : (url.nScheme == INTERNET_SCHEME_HTTPS ? 443 : 80);
    log_line(L"Upload target host=\"%s\" port=%u secure=%s path=\"%s\"",
        host_buf, (unsigned)port,
        bool_to_wide(url.nScheme == INTERNET_SCHEME_HTTPS), path_buf);
    log_line(L"Upload payload dump=%luB event=%s bc1=%s bc2=%s stowed=%s "
             L"attachments=%Iu",
        dump_len, bool_to_wide(have_event), bool_to_wide(have_bc1),
        bool_to_wide(have_bc2), bool_to_wide(have_stowed_stack),
        attachments.size());

    char boundary[64];
    _snprintf_s(boundary, _countof(boundary), _TRUNCATE,
        "----sentry-wer-%08lX-%08lX", (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetTickCount());

    char header_a[128];
    _snprintf_s(header_a, _countof(header_a), _TRUNCATE,
        "Content-Type: multipart/form-data; boundary=%s", boundary);
    wchar_t header_w[128];
    MultiByteToWideChar(CP_UTF8, 0, header_a, -1, header_w, _countof(header_w));

    sentry_stringbuilder_t sb;
    sentry__stringbuilder_init(&sb);
    int err = 0;
    if (have_event && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_EVENT_PART,
            SENTRY_WER_MP_EVENT_PART, event_data, event_len, true,
            "application/octet-stream");
    }
    if (have_bc1 && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_BREADCRUMB1_PART,
            SENTRY_WER_MP_BREADCRUMB1_PART, bc1_data, bc1_len, true,
            "application/octet-stream");
    }
    if (have_bc2 && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_BREADCRUMB2_PART,
            SENTRY_WER_MP_BREADCRUMB2_PART, bc2_data, bc2_len, true,
            "application/octet-stream");
    }
    if (have_stowed_stack && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_STOWED_STACK_PART,
            SENTRY_WER_STOWED_STACK_FILE_A, stowed_stack_data, stowed_stack_len,
            true, "text/plain");
    }
    // Sentry deduplicates multipart parts by their form-data `name` field.
    // Use an indexed name (attachment_0, attachment_1, …) rather than the
    // user filename so that two attachments with the same filename produce
    // two distinct parts.  The human-readable filename is preserved in the
    // separate `filename` parameter of the Content-Disposition header.
    size_t attachment_index = 0;
    for (const auto &attachment : attachments) {
        if (err) {
            break;
        }

        BYTE *attachment_data = nullptr;
        DWORD attachment_len = 0;
        if (!read_file(
                attachment.path.c_str(), &attachment_data, &attachment_len)
            || !attachment_len) {
            continue;
        }

        char name_buf[32];
        _snprintf_s(name_buf, _countof(name_buf), _TRUNCATE, "attachment_%zu",
            attachment_index++);
        err = append_part_fn(&sb, boundary, name_buf,
            attachment.filename.c_str(), attachment_data, attachment_len, true,
            attachment.content_type.c_str());
        HeapFree(GetProcessHeap(), 0, attachment_data);
    }
    if (!err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_MINIDUMP_PART,
            "dump.dmp", dump_data, dump_len, false, "application/octet-stream");
    }
    if (!err) {
        char footer[96];
        int written
            = snprintf(footer, sizeof(footer), "\r\n--%s--\r\n", boundary);
        if (written < 0 || (size_t)written >= sizeof(footer)
            || sentry__stringbuilder_append(&sb, footer)) {
            err = 1;
        }
    }

    bool ok = false;
    if (!err) {
        size_t body_len = sentry__stringbuilder_len(&sb);
        char *body = sentry__stringbuilder_into_string(&sb);
        const wchar_t *user_agent
            = ctx->user_agent[0] ? ctx->user_agent : L"sentry-wer/1.0";
        const wchar_t *proxy = ctx->proxy[0] ? ctx->proxy : NULL;
        HINTERNET session = sentry__wer_winhttp_open_session(user_agent, proxy);
        if (session) {
            sentry_wer_winhttp_result_t result;
            if (sentry__wer_winhttp_simple_post(session, host_buf, port,
                    url.nScheme == INTERNET_SCHEME_HTTPS, path_buf, header_w,
                    (const unsigned char *)body, body_len, &result)
                == 0) {
                log_line(L"Upload HTTP status=%u rate_limited=%s",
                    result.status_code, bool_to_wide(result.rate_limited));
                ok = result.status_code >= 200 && result.status_code < 300;
            } else {
                log_line(L"Upload POST failed");
            }
            WinHttpCloseHandle(session);
        } else {
            log_line(L"WinHTTP session open failed");
        }
        sentry_free(body);
    } else {
        sentry__stringbuilder_cleanup(&sb);
        log_line(L"Failed to build multipart upload body");
    }

    if (ok) {
        write_uploaded_marker();
    }

    if (dump_data) {
        HeapFree(GetProcessHeap(), 0, dump_data);
    }
    if (event_data) {
        HeapFree(GetProcessHeap(), 0, event_data);
    }
    if (bc1_data) {
        HeapFree(GetProcessHeap(), 0, bc1_data);
    }
    if (bc2_data) {
        HeapFree(GetProcessHeap(), 0, bc2_data);
    }
    if (stowed_stack_data) {
        HeapFree(GetProcessHeap(), 0, stowed_stack_data);
    }

    return ok;
}

static bool
read_runtime_context(const PWER_RUNTIME_EXCEPTION_INFORMATION info,
    PVOID remote_ctx, sentry_wer_runtime_context *dst)
{
    // Reads the sentry_wer_runtime_context struct from the crashing process.
    // We first read just the header to check version and size, then do a
    // second read for the full payload (capped to our local struct size for
    // forward-compatibility with newer versions).
    if (!info || !info->hProcess || !remote_ctx || !dst) {
        return false;
    }

    sentry_wer_runtime_context_header header = { };
    SIZE_T read = 0;
    if (!ReadProcessMemory(
            info->hProcess, remote_ctx, &header, sizeof(header), &read)
        || read != sizeof(header)) {
        return false;
    }

    if (header.version == 0
        || header.version > SENTRY_WER_RUNTIME_CONTEXT_VERSION
        || header.size < SENTRY_WER_RUNTIME_CONTEXT_MIN_SIZE) {
        return false;
    }

    memset(dst, 0, sizeof(*dst));
    SIZE_T to_read = header.size;
    if (to_read > sizeof(*dst)) {
        to_read = sizeof(*dst);
    }

    read = 0;
    if (!ReadProcessMemory(info->hProcess, remote_ctx, dst, to_read, &read)
        || read < SENTRY_WER_RUNTIME_CONTEXT_MIN_SIZE) {
        return false;
    }

    return true;
}

static HRESULT CALLBACK
out_of_process_exception_event_callback_impl(PVOID ctx,
    const PWER_RUNTIME_EXCEPTION_INFORMATION info, BOOL *claimed,
    PWSTR event_name, PDWORD event_size, PDWORD signature_count)
{
    sentry_wer_runtime_context ctx_copy = { };
    wer_status status = WER_STATUS_OK;

    log_line(L"Callback enter werfault_pid=%lu target_pid=%lu target_tid=%lu "
             L"code=0x%08lX addr=%p",
        GetCurrentProcessId(),
        info && info->hProcess ? GetProcessId(info->hProcess) : 0,
        info && info->hThread ? GetThreadId(info->hThread) : 0,
        info ? info->exceptionRecord.ExceptionCode : 0,
        info ? info->exceptionRecord.ExceptionAddress : nullptr);

    if (!read_runtime_context(info, ctx, &ctx_copy)) {
        log_line(L"Runtime context read failed remote_ctx=%p", ctx);
        return log_and_status_to_hresult(WER_STATUS_CONTEXT_READ_FAIL);
    }

    g_state.run_path = ctx_copy.run_path;
    g_state.database_path = ctx_copy.database_path;
    log_line(L"Runtime context version=%u size=%u flags=0x%08lX run=\"%s\" "
             L"upload_url=%s consent_required=%s",
        ctx_copy.version, ctx_copy.size, ctx_copy.flags,
        g_state.run_path.c_str(), bool_to_wide(ctx_copy.minidump_url[0] != 0),
        bool_to_wide((ctx_copy.flags & SENTRY_WER_FLAG_REQUIRE_CONSENT) != 0));

    if (claimed) {
        // Leave *claimed = FALSE so WER still shows its normal crash dialog
        // and generates its own report in addition to ours.
        *claimed = FALSE;
    }
    if (signature_count) {
        *signature_count = 0;
    }
    if (event_name && event_size) {
        const wchar_t *name = L"sentry-wer";
        size_t needed = wcslen(name) + 1;
        if (*event_size >= needed) {
            wcscpy_s(event_name, *event_size, name);
        }
        *event_size = (DWORD)needed;
    }

    std::wstring dump_path;
    if (!write_minidump(info, &dump_path)) {
        return log_and_status_to_hresult(WER_STATUS_DUMP_WRITE_FAIL);
    }

    write_crash_marker();

    bool has_consent = has_user_consent(&ctx_copy);

    if (!ctx_copy.minidump_url[0]) {
        log_line(L"Skipping upload because minidump_url is empty");
        status = WER_STATUS_NO_MINIDUMP_URL;
    } else if (!has_consent) {
        log_line(L"Skipping upload because user consent is missing");
        status = WER_STATUS_CONSENT_REQUIRED;
    } else if (!upload_dump(&ctx_copy, dump_path)) {
        status = WER_STATUS_UPLOAD_FAIL;
    }

    return log_and_status_to_hresult(status);
}

// Top-level WER callback exported by name. WerFault.exe loads the DLL and calls
// this directly. The try/catch boundary prevents any C++ exception (including
// std::bad_alloc) from escaping into WerFault.exe and crashing the error
// reporter.
extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventCallback(PVOID ctx,
    const PWER_RUNTIME_EXCEPTION_INFORMATION info, BOOL *claimed,
    PWSTR event_name, PDWORD event_size, PDWORD signature_count)
{
    try {
        return out_of_process_exception_event_callback_impl(
            ctx, info, claimed, event_name, event_size, signature_count);
    } catch (const std::bad_alloc &) {
        log_line(L"WER callback failed with out-of-memory");
    } catch (...) {
        log_line(L"WER callback failed with an unexpected C++ exception");
    }

    return E_FAIL;
}

// Required WER exports. We don't use event signatures or debugger launch;
// returning E_FAIL tells WER to proceed with its default behavior.
extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventSignatureCallback(PVOID,
    const PWER_RUNTIME_EXCEPTION_INFORMATION, DWORD, PWSTR, PDWORD, PWSTR,
    PDWORD)
{
    return E_FAIL;
}

extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventDebuggerLaunchCallback(PVOID,
    const PWER_RUNTIME_EXCEPTION_INFORMATION, PBOOL, PWSTR, PDWORD, PBOOL)
{
    return E_FAIL;
}

BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t module_path[MAX_PATH] = { };
        DWORD module_len
            = GetModuleFileNameW(instance, module_path, _countof(module_path));
        log_line(L"DLL_PROCESS_ATTACH pid=%lu tid=%lu module=\"%s\"",
            GetCurrentProcessId(), GetCurrentThreadId(),
            module_len ? module_path : L"<unknown>");
    } else if (reason == DLL_PROCESS_DETACH) {
        log_line(L"DLL_PROCESS_DETACH pid=%lu tid=%lu", GetCurrentProcessId(),
            GetCurrentThreadId());
    }
    return TRUE;
}
