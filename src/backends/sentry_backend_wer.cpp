extern "C" {
#include "sentry_alloc.h"
#include "sentry_attachment.h"
#include "sentry_backend.h"
#include "sentry_core.h"
#include "sentry_database.h"
#include "sentry_envelope.h"
#include "sentry_logs.h"
#include "sentry_metrics.h"
#include "sentry_options.h"
#include "sentry_path.h"
#include "sentry_screenshot.h"
#include "sentry_session.h"
#include "sentry_transport.h"
#include "sentry_utils.h"
#include "sentry_uuid.h"
#include "sentry_value.h"
#include "transports/sentry_disk_transport.h"
}

#include "wer/sentry_wer_common.h"
#include "wer/sentry_wer_long_path.h"

#include <appmodel.h>
#include <strsafe.h>
#include <werapi.h>
#include <windows.h>

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <new>
#include <string>
#include <vector>

extern "C" {

typedef HRESULT(WINAPI *pWerRegisterRuntimeExceptionModule)(PCWSTR, PVOID);
typedef HRESULT(WINAPI *pWerUnregisterRuntimeExceptionModule)(PCWSTR, PVOID);

struct wer_state_t {
    sentry_path_t *event_path = nullptr;
    sentry_path_t *breadcrumb1_path = nullptr;
    sentry_path_t *breadcrumb2_path = nullptr;
    sentry_path_t *attachments_path = nullptr;
    sentry_path_t *last_crash_path = nullptr;
    size_t num_breadcrumbs = 0;
    // Serialises concurrent wer_backend_add_breadcrumb calls. Guards both the
    // num_breadcrumbs counter and the file writes so that the rotation boundary
    // (first_breadcrumb) and the actual write are always atomically paired.
    std::mutex breadcrumb_mutex;
    // Prevents concurrent scope flushes (e.g. breadcrumb add racing with
    // except).
    std::atomic<bool> scope_flush { false };
    sentry_uuid_t crash_event_id { };
    std::wstring registered_module_path;
    // Allocated with VirtualAlloc so it lives in a stable, readable page that
    // sentry_wer_module.dll can reach via ReadProcessMemory from WerFault.exe.
    sentry_wer_runtime_context *runtime_ctx = nullptr;
};

// Run directories older than this without a recovered envelope are pruned.
static const time_t SENTRY_WER_STALE_RUN_MAX_AGE = 7 * 24 * 60 * 60;

// Attachment metadata file format: repeated triplets of NUL-terminated strings
// (absolute_path \0 filename \0 content_type \0). Absolute paths are stored so
// the WER module (running in WerFault.exe without the app's cwd) can find them.
static void
append_attachment_field(std::vector<char> &buffer, const char *value)
{
    if (value && value[0]) {
        buffer.insert(buffer.end(), value, value + strlen(value));
    }
    buffer.push_back('\0');
}

static char *
wer_clone_n(const char *value, size_t len)
{
    char *copy = (char *)sentry_malloc(len + 1);
    if (!copy) {
        return nullptr;
    }

    memcpy(copy, value, len);
    copy[len] = '\0';
    return copy;
}

static bool
wer_read_cstring_field(const char *data, size_t len, size_t *offset, char **out)
{
    if (!data || !offset || !out || *offset > len) {
        return false;
    }

    size_t start = *offset;
    while (*offset < len && data[*offset] != '\0') {
        (*offset)++;
    }
    if (*offset >= len) {
        return false;
    }

    *out = wer_clone_n(data + start, *offset - start);
    (*offset)++;
    return *out != nullptr;
}

static sentry_value_t
wer_backend_read_msgpack_file(const sentry_path_t *path)
{
    size_t size = 0;
    char *data = sentry__path_read_to_buffer(path, &size);
    if (!data) {
        return sentry_value_new_null();
    }

    sentry_value_t value = sentry__value_from_msgpack(data, size);
    sentry_free(data);
    return value;
}

static sentry_attachment_t *
wer_backend_read_attachment_metadata(const sentry_path_t *attachments_path)
{
    if (!attachments_path || !sentry__path_is_file(attachments_path)) {
        return nullptr;
    }

    size_t len = 0;
    char *data = sentry__path_read_to_buffer(attachments_path, &len);
    if (!data || !len) {
        sentry_free(data);
        return nullptr;
    }

    sentry_attachment_t *attachments = nullptr;
    size_t offset = 0;
    while (offset < len) {
        char *path_utf8 = nullptr;
        char *filename = nullptr;
        char *content_type = nullptr;

        if (!wer_read_cstring_field(data, len, &offset, &path_utf8)
            || !wer_read_cstring_field(data, len, &offset, &filename)
            || !wer_read_cstring_field(data, len, &offset, &content_type)) {
            sentry_free(path_utf8);
            sentry_free(filename);
            sentry_free(content_type);
            break;
        }

        sentry_path_t *path = sentry__path_from_str(path_utf8);
        sentry_attachment_t *attachment
            = path ? sentry__attachment_from_path(path) : nullptr;
        if (attachment) {
            if (filename[0]) {
                attachment->filename = sentry__path_from_str(filename);
            }
            sentry__attachments_add(&attachments, attachment, ATTACHMENT,
                content_type[0] ? content_type : nullptr);
        }

        sentry_free(path_utf8);
        sentry_free(filename);
        sentry_free(content_type);
    }

    sentry_free(data);
    return attachments;
}

static sentry_path_t *
wer_backend_find_first_minidump(const sentry_path_t *run_dir)
{
    sentry_pathiter_t *iter = sentry__path_iter_directory(run_dir);
    if (!iter) {
        return nullptr;
    }

    const sentry_path_t *path = nullptr;
    sentry_path_t *result = nullptr;
    while ((path = sentry__pathiter_next(iter)) != nullptr) {
        if (sentry__path_is_file(path)
            && sentry__path_ends_with(path, ".dmp")) {
            result = sentry__path_clone(path);
            break;
        }
    }

    sentry__pathiter_free(iter);
    return result;
}

static bool
wer_backend_run_has_envelope(const sentry_path_t *run_dir)
{
    // If a .envelope file already exists, the run was already recovered on a
    // previous startup; skip it to avoid double-submission.
    sentry_pathiter_t *iter = sentry__path_iter_directory(run_dir);
    if (!iter) {
        return false;
    }

    bool has_envelope = false;
    const sentry_path_t *path = nullptr;
    while ((path = sentry__pathiter_next(iter)) != nullptr) {
        if (sentry__path_is_file(path)
            && sentry__path_ends_with(path, ".envelope")) {
            has_envelope = true;
            break;
        }
    }

    sentry__pathiter_free(iter);
    return has_envelope;
}

static sentry_envelope_t *
wer_backend_staged_run_to_envelope(
    const sentry_path_t *run_dir, const sentry_options_t *options)
{
    // Recovery path: reconstruct an envelope from the staged msgpack files and
    // minidump left by sentry_wer_module.dll after a WER-handled crash.
    sentry_path_t *event_path
        = sentry__path_join_str(run_dir, SENTRY_WER_EVENT_FILE_A);
    sentry_path_t *breadcrumb1_path
        = sentry__path_join_str(run_dir, SENTRY_WER_BREADCRUMB1_FILE_A);
    sentry_path_t *breadcrumb2_path
        = sentry__path_join_str(run_dir, SENTRY_WER_BREADCRUMB2_FILE_A);
    sentry_path_t *attachments_path
        = sentry__path_join_str(run_dir, SENTRY_WER_ATTACHMENTS_FILE_A);
    sentry_path_t *stowed_stack_path
        = sentry__path_join_str(run_dir, SENTRY_WER_STOWED_STACK_FILE_A);
    sentry_path_t *minidump_path = wer_backend_find_first_minidump(run_dir);

    sentry_value_t event = sentry_value_new_null();
    sentry_value_t breadcrumbs1 = sentry_value_new_null();
    sentry_value_t breadcrumbs2 = sentry_value_new_null();
    sentry_attachment_t *attachments = nullptr;
    sentry_envelope_t *envelope = nullptr;

    if (event_path && sentry__path_is_file(event_path)) {
        event = wer_backend_read_msgpack_file(event_path);
    }
    if (breadcrumb1_path && sentry__path_is_file(breadcrumb1_path)) {
        breadcrumbs1 = wer_backend_read_msgpack_file(breadcrumb1_path);
    }
    if (breadcrumb2_path && sentry__path_is_file(breadcrumb2_path)) {
        breadcrumbs2 = wer_backend_read_msgpack_file(breadcrumb2_path);
    }
    if (attachments_path) {
        attachments = wer_backend_read_attachment_metadata(attachments_path);
    }
    if (stowed_stack_path && sentry__path_is_file(stowed_stack_path)) {
        sentry__attachments_add_path(&attachments,
            sentry__path_clone(stowed_stack_path), ATTACHMENT, "text/plain");
    }
    if (minidump_path) {
        sentry__attachments_add_path(
            &attachments, minidump_path, MINIDUMP, nullptr);
        minidump_path = nullptr;
    }

    if (!sentry_value_is_null(event)) {
        envelope = sentry__envelope_new();
        if (envelope && options->dsn && options->dsn->is_valid) {
            sentry__envelope_set_header(envelope, "dsn",
                sentry_value_new_string(sentry_options_get_dsn(options)));
        }
    }

    if (envelope) {
        sentry_value_set_by_key(event, "breadcrumbs",
            sentry__value_merge_breadcrumbs(
                breadcrumbs1, breadcrumbs2, options->max_breadcrumbs));
        if (sentry__envelope_add_event(envelope, event)) {
            sentry__envelope_add_attachments(envelope, attachments);
        } else {
            sentry_value_decref(event);
            sentry_envelope_free(envelope);
            envelope = nullptr;
        }
    } else {
        sentry_value_decref(event);
    }

    sentry_value_decref(breadcrumbs1);
    sentry_value_decref(breadcrumbs2);
    sentry__attachments_free(attachments);
    sentry__path_free(event_path);
    sentry__path_free(breadcrumb1_path);
    sentry__path_free(breadcrumb2_path);
    sentry__path_free(attachments_path);
    sentry__path_free(stowed_stack_path);
    sentry__path_free(minidump_path);

    return envelope;
}

static bool
wer_backend_write_recovered_envelope(
    const sentry_path_t *run_dir, const sentry_envelope_t *envelope)
{
    // Materializes the recovered envelope to a .envelope file in the run
    // directory so that sentry__process_old_runs() can upload it on the
    // next startup, just like any other pending envelope.
    sentry_uuid_t event_id = sentry__envelope_get_event_id(envelope);
    if (sentry_uuid_is_nil(&event_id)) {
        event_id = sentry_uuid_new_v4();
    }

    char *filename = sentry__uuid_as_filename(&event_id, ".envelope");
    if (!filename) {
        return false;
    }

    sentry_path_t *envelope_path = sentry__path_join_str(run_dir, filename);
    sentry_free(filename);
    if (!envelope_path) {
        return false;
    }

    int rv = sentry_envelope_write_to_path(envelope, envelope_path);
    sentry__path_free(envelope_path);
    return rv == 0;
}

static void
wer_backend_prepare_old_runs(const sentry_options_t *options)
{
    // For each old .run directory that does not yet have a recovered envelope:
    // reconstruct an envelope from the staged WER artifacts and write it so
    // sentry__process_old_runs() can replay it. Skip the current run and any
    // run that another process has locked.
    if (!options || !options->database_path || !options->run
        || !options->run->run_path) {
        return;
    }

    sentry_pathiter_t *db_iter
        = sentry__path_iter_directory(options->database_path);
    if (!db_iter) {
        return;
    }

    const sentry_path_t *run_dir = nullptr;
    while ((run_dir = sentry__pathiter_next(db_iter)) != nullptr) {
        if (!sentry__path_is_dir(run_dir)
            || !sentry__path_ends_with(run_dir, ".run")
            || strcmp(options->run->run_path->path, run_dir->path) == 0
            || wer_backend_run_has_envelope(run_dir)) {
            continue;
        }

        sentry_path_t *lockfile = sentry__path_append_str(run_dir, ".lock");
        sentry_filelock_t *lock
            = lockfile ? sentry__filelock_new(lockfile) : nullptr;
        if (!lock) {
            continue;
        }

        if (!sentry__filelock_try_lock(lock)) {
            sentry__filelock_free(lock);
            continue;
        }

        sentry_envelope_t *envelope
            = wer_backend_staged_run_to_envelope(run_dir, options);
        if (envelope
            && !wer_backend_write_recovered_envelope(run_dir, envelope)) {
            SENTRY_WARNF(
                "failed to materialize recovered WER envelope in \"%s\"",
                run_dir->path);
        }
        sentry_envelope_free(envelope);
        sentry__filelock_free(lock);
    }

    sentry__pathiter_free(db_iter);
}

static void
wer_backend_sync_attachments(
    const sentry_path_t *attachments_path, sentry_attachment_t *attachments)
{
    if (!attachments_path) {
        return;
    }

    std::vector<char> buffer;
    bool have_attachments = false;
    for (sentry_attachment_t *it = attachments; it; it = it->next) {
        if (!it->path || !it->path->path) {
            continue;
        }

        sentry_path_t *absolute_path = sentry__path_absolute(it->path);
        const sentry_path_t *stored_path
            = absolute_path ? absolute_path : it->path;

        const char *filename
            = sentry__path_filename(it->filename ? it->filename : it->path);
        if (!filename || !filename[0]) {
            sentry__path_free(absolute_path);
            continue;
        }

        append_attachment_field(buffer, stored_path->path);
        append_attachment_field(buffer, filename);
        append_attachment_field(buffer, it->content_type);
        sentry__path_free(absolute_path);
        have_attachments = true;
    }

    if (!have_attachments) {
        sentry__path_remove(attachments_path);
        return;
    }

    if (sentry__path_write_buffer(
            attachments_path, buffer.data(), buffer.size())
        != 0) {
        SENTRY_WARN("flushing WER attachment metadata failed");
    }
}

static bool
wer_backend_ensure_attachment_path(
    const wer_state_t *state, sentry_attachment_t *attachment)
{
    // Buffer attachments have no on-disk path yet. Create a UUID-named
    // subdirectory inside the run folder so the filename is preserved and
    // the file remains isolated from the top-level run artifacts.
    if (!state || !state->event_path || !attachment || !attachment->filename) {
        return false;
    }

    sentry_uuid_t uuid = sentry_uuid_new_v4();
    char uuid_str[37];
    sentry_uuid_as_string(&uuid, uuid_str);

    sentry_path_t *run_path = sentry__path_dir(state->event_path);
    sentry_path_t *base_path
        = run_path ? sentry__path_join_str(run_path, uuid_str) : nullptr;
    sentry__path_free(run_path);

    if (!base_path || sentry__path_create_dir_all(base_path) != 0) {
        sentry__path_free(base_path);
        return false;
    }

    sentry_path_t *old_path = attachment->path;
    attachment->path = sentry__path_join_str(
        base_path, sentry__path_filename(attachment->filename));

    sentry__path_free(base_path);
    sentry__path_free(old_path);
    return attachment->path != nullptr;
}

static void
wer_backend_flush_scope_to_event(const sentry_path_t *event_path,
    const sentry_options_t *options, sentry_value_t crash_event)
{
    SENTRY_WITH_SCOPE (scope) {
        sentry__scope_apply_to_event(
            scope, options, crash_event, SENTRY_SCOPE_NONE);
    }

    size_t mpack_size = 0;
    char *mpack = sentry_value_to_msgpack(crash_event, &mpack_size);
    sentry_value_decref(crash_event);
    if (!mpack) {
        return;
    }

    int rv = sentry__path_write_buffer(event_path, mpack, mpack_size);
    sentry_free(mpack);

    if (rv != 0) {
        SENTRY_WARN("flushing WER scope to msgpack failed");
    }
}

static void
wer_backend_flush_scope(
    sentry_backend_t *backend, const sentry_options_t *options)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !state->event_path) {
        return;
    }

    // CAS from false→true; if another flush is already running (concurrent
    // breadcrumb callback), bail out rather than writing a partial scope.
    bool expected = false;
    if (!state->scope_flush.compare_exchange_strong(expected, true,
            std::memory_order_acquire, std::memory_order_relaxed)) {
        return;
    }

    sentry_value_t event
        = sentry__value_new_event_with_id(&state->crash_event_id);
    sentry_value_set_by_key(
        event, "level", sentry__value_new_level(SENTRY_LEVEL_FATAL));
    wer_backend_flush_scope_to_event(state->event_path, options, event);

    SENTRY_WITH_SCOPE (scope) {
        wer_backend_sync_attachments(
            state->attachments_path, scope->attachments);
    }

    state->scope_flush.store(false, std::memory_order_release);
}

static void
wer_backend_add_breadcrumb(sentry_backend_t *backend, sentry_value_t breadcrumb,
    const sentry_options_t *options)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }

    size_t max_breadcrumbs = options->max_breadcrumbs;
    if (!max_breadcrumbs) {
        return;
    }

    // Serialise so that the rotation decision (first_breadcrumb / which file)
    // and the subsequent write are always atomic with respect to concurrent
    // calls from multiple threads.
    std::lock_guard<std::mutex> lk(state->breadcrumb_mutex);

    // Breadcrumbs are written to two alternating files
    // (breadcrumb1/breadcrumb2), each holding up to max_breadcrumbs entries.
    // The first write to a file overwrites it; subsequent writes append. This
    // mirrors the crashpad/inproc breadcrumb rotation so the WER module can
    // merge both files at crash time.
    bool first_breadcrumb = state->num_breadcrumbs % max_breadcrumbs == 0;
    const sentry_path_t *breadcrumb_file
        = state->num_breadcrumbs % (max_breadcrumbs * 2) < max_breadcrumbs
        ? state->breadcrumb1_path
        : state->breadcrumb2_path;
    state->num_breadcrumbs++;

    if (!breadcrumb_file) {
        return;
    }

    size_t mpack_size = 0;
    char *mpack = sentry_value_to_msgpack(breadcrumb, &mpack_size);
    if (!mpack) {
        return;
    }

    int rv = first_breadcrumb
        ? sentry__path_write_buffer(breadcrumb_file, mpack, mpack_size)
        : sentry__path_append_buffer(breadcrumb_file, mpack, mpack_size);
    sentry_free(mpack);

    if (rv != 0) {
        SENTRY_WARN("flushing WER breadcrumb to msgpack failed");
    }
}

static bool
wer_process_has_package_identity(void)
{
    using get_current_package_full_name_t = LONG(WINAPI *)(UINT32 *, PWSTR);

    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) {
        return false;
    }

    auto fn = reinterpret_cast<get_current_package_full_name_t>(
        GetProcAddress(kernel, "GetCurrentPackageFullName"));
    if (!fn) {
        return false;
    }

    UINT32 len = 0;
    LONG rc = fn(&len, nullptr);
    if (rc == APPMODEL_ERROR_NO_PACKAGE) {
        return false;
    }

    return rc == ERROR_INSUFFICIENT_BUFFER && len > 0;
}

static bool
wer_set_registry_value_via_regexe(const wchar_t *dll_path)
{
    // MSIX apps have their registry writes virtualized into the package
    // container. WerFault.exe runs without the package identity and reads the
    // real HKCU hive, so we must invoke reg.exe as an external process to
    // write to the actual registry key.
    wchar_t system_dir[MAX_PATH];
    UINT sys_len = GetSystemDirectoryW(system_dir, _countof(system_dir));
    if (sys_len == 0 || sys_len >= _countof(system_dir)) {
        return false;
    }

    wchar_t reg_path[MAX_PATH];
    if (FAILED(StringCchPrintfW(
            reg_path, _countof(reg_path), L"%ls\\reg.exe", system_dir))) {
        return false;
    }

    const wchar_t *template_fmt
        = L"\"%ls\" ADD \"HKCU\\Software\\Microsoft\\Windows\\Windows Error "
          L"Reporting\\RuntimeExceptionHelperModules\" /v \"%ls\" /t "
          L"REG_DWORD /d 1 /f";
    int cmd_len = _scwprintf(template_fmt, reg_path, dll_path);
    if (cmd_len <= 0) {
        return false;
    }

    std::vector<wchar_t> cmd((size_t)cmd_len + 1, L'\0');
    if (FAILED(StringCchPrintfW(
            cmd.data(), cmd.size(), template_fmt, reg_path, dll_path))) {
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { };
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        SENTRY_WARN("failed launching reg.exe for WER module registration");
        return false;
    }

    WaitForSingleObject(pi.hProcess, 4000);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exit_code != 0) {
        SENTRY_WARN(
            "reg.exe exited with a non-zero code while adding the WER module");
        return false;
    }

    return true;
}

static bool
wer_register_runtime_module(
    const wchar_t *dll_path, void *ctx, bool has_package_identity)
{
    // Both steps are required: WerRegisterRuntimeExceptionModule registers the
    // in-process callback, and the HKCU registry key tells WerFault.exe which
    // DLL to load when the process crashes. `ctx` is the VirtualAlloc'd
    // runtime_context pointer, passed back to the callback as its first
    // argument.
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) {
        return false;
    }

    auto fn_register = reinterpret_cast<pWerRegisterRuntimeExceptionModule>(
        GetProcAddress(kernel, "WerRegisterRuntimeExceptionModule"));
    if (!fn_register) {
        SENTRY_WARN("WerRegisterRuntimeExceptionModule not available");
        return false;
    }

    bool reg_ok = false;
    if (has_package_identity) {
        reg_ok = wer_set_registry_value_via_regexe(dll_path);
    } else {
        constexpr DWORD one = 1;
        LSTATUS reg_res = RegSetKeyValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\Windows Error "
            L"Reporting\\RuntimeExceptionHelperModules",
            dll_path, REG_DWORD, &one, sizeof(one));
        reg_ok = reg_res == ERROR_SUCCESS;
        if (!reg_ok) {
            SENTRY_WARN("registering the WER module in HKCU failed");
        } else {
            RegFlushKey(HKEY_CURRENT_USER);
        }
    }

    HRESULT hr = fn_register(dll_path, ctx);
    if (FAILED(hr)) {
        if (reg_ok) {
            RegDeleteKeyValueW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\Windows Error "
                L"Reporting\\RuntimeExceptionHelperModules",
                dll_path);
        }
        SENTRY_WARNF("WerRegisterRuntimeExceptionModule failed hr=0x%08x", hr);
        return false;
    }

    return true;
}

static void
wer_unregister_runtime_module(const wchar_t *dll_path, void *ctx)
{
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) {
        return;
    }

    auto fn_unregister = reinterpret_cast<pWerUnregisterRuntimeExceptionModule>(
        GetProcAddress(kernel, "WerUnregisterRuntimeExceptionModule"));
    if (!fn_unregister) {
        return;
    }

    fn_unregister(dll_path, ctx);
}

static void
narrow_to_wide_opt(const char *src, wchar_t *dst, size_t cap)
{
    if (!dst || !cap) {
        return;
    }

    if (!src || !src[0]) {
        dst[0] = L'\0';
        return;
    }

    int rv = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)cap);
    if (rv == 0) {
        dst[0] = L'\0';
    } else {
        dst[cap - 1] = L'\0';
    }
}

static bool
wer_copy_file_long_path(const wchar_t *src, const wchar_t *dst)
{
    std::wstring src_path = sentry_wer_to_extended_path(src);
    std::wstring dst_path = sentry_wer_to_extended_path(dst);
    if (src_path.empty() || dst_path.empty()) {
        return false;
    }

    return CopyFileW(src_path.c_str(), dst_path.c_str(), FALSE) != 0;
}

static int
wer_backend_startup(sentry_backend_t *backend, const sentry_options_t *options)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !options || !options->run || !options->run->run_path) {
        return 1;
    }

    sentry_path_t *current_run_folder = options->run->run_path;
    state->crash_event_id = sentry__new_event_id();
    state->event_path
        = sentry__path_join_str(current_run_folder, SENTRY_WER_EVENT_FILE_A);
    state->breadcrumb1_path = sentry__path_join_str(
        current_run_folder, SENTRY_WER_BREADCRUMB1_FILE_A);
    state->breadcrumb2_path = sentry__path_join_str(
        current_run_folder, SENTRY_WER_BREADCRUMB2_FILE_A);
    state->attachments_path = sentry__path_join_str(
        current_run_folder, SENTRY_WER_ATTACHMENTS_FILE_A);
    if (options->database_path) {
        state->last_crash_path = sentry__path_join_str(
            options->database_path, SENTRY_WER_LAST_CRASH_FILE_A);
    }

    if (!state->event_path || !state->breadcrumb1_path
        || !state->breadcrumb2_path || !state->attachments_path) {
        return 1;
    }

    wer_backend_prepare_old_runs(options);

    sentry__path_touch(state->event_path);
    sentry__path_touch(state->breadcrumb1_path);
    sentry__path_touch(state->breadcrumb2_path);

    sentry_path_t *resolved_module_path = nullptr;
    if (options->handler_path && options->handler_path->path) {
        if (sentry__path_ends_with(options->handler_path, ".dll")) {
            resolved_module_path = sentry__path_clone(options->handler_path);
        } else {
            resolved_module_path = sentry__path_join_str(
                options->handler_path, "sentry_wer_module.dll");
        }
    }

    if (!resolved_module_path) {
        if (sentry_path_t *current_exe = sentry__path_current_exe()) {
            sentry_path_t *exe_dir = sentry__path_dir(current_exe);
            sentry__path_free(current_exe);
            if (exe_dir) {
                resolved_module_path
                    = sentry__path_join_str(exe_dir, "sentry_wer_module.dll");
                sentry__path_free(exe_dir);
            }
        }
    }

    sentry_path_t *absolute_module_path
        = sentry__path_absolute(resolved_module_path);
    sentry__path_free(resolved_module_path);

    if (!absolute_module_path || !sentry__path_is_file(absolute_module_path)) {
        SENTRY_WARN("unable to start WER backend, invalid handler_path");
        sentry__path_free(absolute_module_path);
        return 1;
    }

    state->runtime_ctx = static_cast<sentry_wer_runtime_context *>(
        VirtualAlloc(NULL, sizeof(*state->runtime_ctx),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    // VirtualAlloc (not new/malloc) so the allocation is page-aligned and
    // guaranteed readable by ReadProcessMemory from sentry_wer_module.dll.
    if (!state->runtime_ctx) {
        sentry__path_free(absolute_module_path);
        return 1;
    }

    memset(state->runtime_ctx, 0, sizeof(*state->runtime_ctx));
    state->runtime_ctx->version = SENTRY_WER_RUNTIME_CONTEXT_VERSION;
    state->runtime_ctx->size = sizeof(*state->runtime_ctx);
    if (current_run_folder->path_w) {
        wcsncpy_s(state->runtime_ctx->run_path,
            _countof(state->runtime_ctx->run_path), current_run_folder->path_w,
            _TRUNCATE);
    }
    if (options->database_path && options->database_path->path_w) {
        wcsncpy_s(state->runtime_ctx->database_path,
            _countof(state->runtime_ctx->database_path),
            options->database_path->path_w, _TRUNCATE);
    }

    if (options->dsn && options->dsn->is_valid) {
        const char *ua
            = options->user_agent ? options->user_agent : SENTRY_SDK_USER_AGENT;
        char *full_url = sentry__dsn_get_minidump_url(options->dsn, ua);
        if (full_url) {
            MultiByteToWideChar(CP_UTF8, 0, full_url, -1,
                state->runtime_ctx->minidump_url,
                (int)_countof(state->runtime_ctx->minidump_url));
            state->runtime_ctx
                ->minidump_url[_countof(state->runtime_ctx->minidump_url) - 1]
                = L'\0';
            sentry_free(full_url);
        }
    }

    narrow_to_wide_opt(options->proxy, state->runtime_ctx->proxy,
        _countof(state->runtime_ctx->proxy));
    narrow_to_wide_opt(options->user_agent, state->runtime_ctx->user_agent,
        _countof(state->runtime_ctx->user_agent));

    if (options->require_user_consent) {
        state->runtime_ctx->flags |= SENTRY_WER_FLAG_REQUIRE_CONSENT;
    }

    bool has_package_identity = wer_process_has_package_identity();
    if (has_package_identity) {
        // WerFault.exe runs without the app's MSIX package identity and cannot
        // load a DLL from inside the package directory. Copy the module to the
        // database folder (a normal filesystem path) and register that copy.
        const sentry_path_t *cache_root = options->database_path
            ? options->database_path
            : current_run_folder;
        if (cache_root) {
            sentry_path_t *dll_cache_path
                = sentry__path_join_str(cache_root, "sentry_wer_module.dll");
            if (dll_cache_path) {
                if (!wer_copy_file_long_path(
                        absolute_module_path->path_w, dll_cache_path->path_w)) {
                    SENTRY_WARNF("failed copying WER module to a stable cache "
                                 "location gle=%lu",
                        GetLastError());
                    sentry__path_free(dll_cache_path);
                } else {
                    sentry__path_free(absolute_module_path);
                    absolute_module_path = dll_cache_path;
                }
            }
        }
    }

    if (!wer_register_runtime_module(absolute_module_path->path_w,
            state->runtime_ctx, has_package_identity)) {
        sentry__path_free(absolute_module_path);
        VirtualFree(state->runtime_ctx, 0, MEM_RELEASE);
        state->runtime_ctx = nullptr;
        return 1;
    }

    state->registered_module_path
        = sentry_wer_get_full_path(absolute_module_path->path_w);
    if (state->registered_module_path.empty() && absolute_module_path->path_w) {
        state->registered_module_path = absolute_module_path->path_w;
    }
    sentry__path_free(absolute_module_path);

    wer_backend_flush_scope(backend, options);
    return 0;
}

static void
wer_backend_shutdown(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }

    if (!state->registered_module_path.empty()) {
        wer_unregister_runtime_module(
            state->registered_module_path.c_str(), state->runtime_ctx);
        RegDeleteKeyValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\Windows Error "
            L"Reporting\\RuntimeExceptionHelperModules",
            state->registered_module_path.c_str());
        RegFlushKey(HKEY_CURRENT_USER);
        state->registered_module_path.clear();
    }

    if (state->runtime_ctx) {
        VirtualFree(state->runtime_ctx, 0, MEM_RELEASE);
        state->runtime_ctx = nullptr;
    }
}

static uint64_t
wer_backend_last_crash(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !state->last_crash_path) {
        return 0;
    }

    size_t file_size = 0;
    char *contents
        = sentry__path_read_to_buffer(state->last_crash_path, &file_size);
    if (!contents || !file_size) {
        sentry_free(contents);
        return 0;
    }

    uint64_t last_crash = sentry__iso8601_to_usec(contents);
    if (!last_crash) {
        errno = 0;
        char *end_ptr = NULL;
        unsigned long long usec = strtoull(contents, &end_ptr, 10);
        if (errno == 0 && end_ptr != contents) {
            last_crash = (uint64_t)usec;
        }
    }

    sentry_free(contents);
    return last_crash;
}

static void
wer_backend_prune_database(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }

    SENTRY_WITH_OPTIONS (options) {
        if (!options || !options->database_path || !options->run
            || !options->run->run_path) {
            return;
        }

        time_t now = time(NULL);
        sentry_pathiter_t *db_iter
            = sentry__path_iter_directory(options->database_path);
        if (!db_iter) {
            return;
        }

        const sentry_path_t *run_dir = nullptr;
        while ((run_dir = sentry__pathiter_next(db_iter)) != nullptr) {
            if (!sentry__path_is_dir(run_dir)
                || !sentry__path_ends_with(run_dir, ".run")
                || strcmp(options->run->run_path->path, run_dir->path) == 0
                || wer_backend_run_has_envelope(run_dir)) {
                continue;
            }

            time_t age = now - sentry__path_get_mtime(run_dir);
            if (age <= SENTRY_WER_STALE_RUN_MAX_AGE) {
                continue;
            }

            sentry_path_t *lockfile = sentry__path_append_str(run_dir, ".lock");
            sentry_filelock_t *lock
                = lockfile ? sentry__filelock_new(lockfile) : nullptr;
            if (!lock) {
                continue;
            }

            if (sentry__filelock_try_lock(lock)) {
                // Release the fd and remove the adjacent .lock file
                // *before* remove_all.  On Windows an open file handle
                // prevents deletion; sentry__filelock_unlock closes the
                // fd and calls sentry__path_remove on the lock path so
                // the run directory can be fully removed afterwards.
                sentry__filelock_unlock(lock);
                sentry__path_remove_all(run_dir);
            }
            // is_locked is now false, so free only deallocates memory.
            sentry__filelock_free(lock);
        }

        sentry__pathiter_free(db_iter);
    }
}

static void
wer_backend_add_attachment(
    sentry_backend_t *backend, sentry_attachment_t *attachment)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !attachment || !attachment->buf) {
        return;
    }

    if (!attachment->path
        && !wer_backend_ensure_attachment_path(state, attachment)) {
        SENTRY_WARN("failed to assign path for WER buffer attachment");
        return;
    }

    if (sentry__path_write_buffer(
            attachment->path, attachment->buf, attachment->buf_len)
        != 0) {
        SENTRY_WARNF(
            "failed to write WER attachment \"%s\"", attachment->path->path);
    }
}

static void
wer_backend_remove_attachment(
    sentry_backend_t *backend, sentry_attachment_t *attachment)
{
    (void)backend;

    if (attachment && attachment->buf && attachment->path
        && sentry__path_remove(attachment->path) != 0) {
        SENTRY_WARNF(
            "failed to remove WER attachment \"%s\"", attachment->path->path);
    }
}

static void
wer_backend_user_consent_changed(sentry_backend_t *backend)
{
    (void)backend;
}

static void
wer_backend_except(sentry_backend_t *backend, const sentry_ucontext_t *ctx)
{
    // This path runs in-process when the app's own exception handler fires
    // (e.g. via SetUnhandledExceptionFilter). It does NOT run inside the WER
    // module. For crashes that only WER can catch (CoreCLR-intercepted AV,
    // stowed exceptions), only the WER module path executes.
    //
    // For all other crashes both this handler AND the WER module run (WER fires
    // after we return EXCEPTION_CONTINUE_SEARCH).  To prevent a duplicate
    // event we zero the minidump_url in the shared runtime context so the WER
    // module sees no upload URL and skips its own submission.  The WER module
    // still writes a minidump to disk (useful for local post-mortem analysis)
    // but will not attempt an upload.
    SENTRY_WITH_OPTIONS (options) {
        if (!options) {
            return;
        }

        wer_backend_flush_scope(backend, options);
        sentry__write_crash_marker(options);

        if (options->enable_logs) {
            sentry__logs_flush_crash_safe();
        }
        if (options->enable_metrics) {
            sentry__metrics_flush_crash_safe();
        }

        // Suppress the WER module's independent upload now that we are
        // handling the event in-process.  This write is visible to
        // WerFault.exe via ReadProcessMemory because runtime_ctx is backed by
        // a VirtualAlloc'd page.
        auto *state = static_cast<wer_state_t *>(backend->data);
        if (state && state->runtime_ctx) {
            state->runtime_ctx->minidump_url[0] = L'\0';
        }

        // Reuse the stable crash_event_id that was written into the staged
        // __sentry-event file by wer_backend_flush_scope so that both code
        // paths (this one and any future WER module upload) share the same
        // event identifier.
        sentry_value_t event = state
            ? sentry__value_new_event_with_id(&state->crash_event_id)
            : sentry_value_new_event();
        sentry_value_set_by_key(
            event, "level", sentry__value_new_level(SENTRY_LEVEL_FATAL));

        bool should_handle = true;
        if (options->on_crash_func) {
            SENTRY_DEBUG("invoking `on_crash` hook");
            sentry_value_t result
                = options->on_crash_func(ctx, event, options->on_crash_data);
            should_handle = !sentry_value_is_null(result);
            event = result;
        }

        if (!should_handle) {
            SENTRY_DEBUG("event was discarded by the `on_crash` hook");
            sentry_value_decref(event);
            return;
        }

        bool capture_screenshot = options->attach_screenshot;
#ifdef SENTRY_PLATFORM_WINDOWS
        if (capture_screenshot && options->before_screenshot_func) {
            SENTRY_DEBUG("invoking `before_screenshot` hook");
            capture_screenshot = options->before_screenshot_func(
                                     event, options->before_screenshot_data)
                != 0;
        }
#endif

        sentry_envelope_t *envelope = sentry__prepare_event(
            options, event, nullptr, !options->on_crash_func, nullptr);
        if (!envelope) {
            return;
        }

        sentry_session_t *session = sentry__end_current_session_with_status(
            SENTRY_SESSION_STATUS_CRASHED);
        sentry__envelope_add_session(envelope, session);

#ifdef SENTRY_PLATFORM_WINDOWS
        if (capture_screenshot) {
            sentry_attachment_t *screenshot = sentry__attachment_from_path(
                sentry__screenshot_get_path(options));
            if (screenshot && sentry__screenshot_capture(screenshot->path, 0)) {
                sentry__envelope_add_attachment(envelope, screenshot);
            }
            sentry__attachment_free(screenshot);
        }
#endif

        sentry_transport_t *disk_transport
            = sentry_new_disk_transport(options->run);
        sentry__capture_envelope(disk_transport, envelope);
        sentry__transport_dump_queue(disk_transport, options->run);
        sentry_transport_free(disk_transport);
        sentry__transport_dump_queue(options->transport, options->run);
    }
}

static void
wer_backend_free(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }

    sentry__path_free(state->event_path);
    sentry__path_free(state->breadcrumb1_path);
    sentry__path_free(state->breadcrumb2_path);
    sentry__path_free(state->attachments_path);
    sentry__path_free(state->last_crash_path);
    delete state;
}

sentry_backend_t *
sentry__backend_new(void)
{
    auto *backend = SENTRY_MAKE(sentry_backend_t);
    if (!backend) {
        return nullptr;
    }
    memset(backend, 0, sizeof(*backend));

    auto *state = new (std::nothrow) wer_state_t();
    if (!state) {
        sentry_free(backend);
        return nullptr;
    }

    backend->startup_func = wer_backend_startup;
    backend->shutdown_func = wer_backend_shutdown;
    backend->free_func = wer_backend_free;
    backend->except_func = wer_backend_except;
    backend->flush_scope_func = wer_backend_flush_scope;
    backend->add_breadcrumb_func = wer_backend_add_breadcrumb;
    backend->add_attachment_func = wer_backend_add_attachment;
    backend->remove_attachment_func = wer_backend_remove_attachment;
    backend->user_consent_changed_func = wer_backend_user_consent_changed;
    backend->get_last_crash_func = wer_backend_last_crash;
    backend->prune_database_func = wer_backend_prune_database;
    backend->data = state;
    backend->can_capture_after_shutdown = true;

    return backend;
}
}
