#ifndef SENTRY_WER_LONG_PATH_H_INCLUDED
#define SENTRY_WER_LONG_PATH_H_INCLUDED

// Standalone long-path helpers for sentry_wer_module.dll. The module runs
// inside WerFault.exe and cannot use sentry__path_* (which links against the
// main SDK). All file operations use the \\?\  extended-length prefix to bypass
// the MAX_PATH limit, which matters for deep database directories.

#include <windows.h>

#include <string>
#include <vector>

static inline bool
sentry_wer_has_extended_prefix(const wchar_t *path)
{
    return path && wcsncmp(path, L"\\\\?\\", 4) == 0;
}

static inline bool
sentry_wer_is_drive_absolute(const wchar_t *path)
{
    return path
        && ((path[0] >= L'A' && path[0] <= L'Z')
            || (path[0] >= L'a' && path[0] <= L'z'))
        && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

static inline bool
sentry_wer_is_unc_absolute(const wchar_t *path)
{
    return path && path[0] == L'\\' && path[1] == L'\\';
}

static inline std::wstring
sentry_wer_get_full_path(const wchar_t *path)
{
    if (!path || !path[0]) {
        return std::wstring();
    }

    if (sentry_wer_has_extended_prefix(path)
        || sentry_wer_is_drive_absolute(path)
        || sentry_wer_is_unc_absolute(path)) {
        return std::wstring(path);
    }

    DWORD required = GetFullPathNameW(path, 0, nullptr, nullptr);
    if (!required) {
        return std::wstring(path);
    }

    std::vector<wchar_t> buffer(required, L'\0');
    DWORD actual = GetFullPathNameW(path, required, buffer.data(), nullptr);
    if (!actual || actual >= required) {
        return std::wstring(path);
    }

    return std::wstring(buffer.data(), actual);
}

// Resolves the path to an absolute form and prepends the \\?\ (or \\?\UNC\)
// prefix so CreateFileW/MiniDumpWriteDump can handle paths longer than
// MAX_PATH.
static inline std::wstring
sentry_wer_to_extended_path(const wchar_t *path)
{
    std::wstring full_path = sentry_wer_get_full_path(path);
    if (full_path.empty()
        || sentry_wer_has_extended_prefix(full_path.c_str())) {
        return full_path;
    }

    if (sentry_wer_is_unc_absolute(full_path.c_str())) {
        return std::wstring(L"\\\\?\\UNC\\") + full_path.substr(2);
    }

    if (sentry_wer_is_drive_absolute(full_path.c_str())) {
        return std::wstring(L"\\\\?\\") + full_path;
    }

    return full_path;
}

static inline std::wstring
sentry_wer_join_path(const std::wstring &base, const wchar_t *leaf)
{
    if (base.empty() || !leaf || !leaf[0]) {
        return std::wstring();
    }

    std::wstring path(base);
    if (path.back() != L'\\' && path.back() != L'/') {
        path.push_back(L'\\');
    }
    path.append(leaf);
    return path;
}

#endif
