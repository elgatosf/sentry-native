#ifndef SENTRY_WER_COMMON_H_INCLUDED
#define SENTRY_WER_COMMON_H_INCLUDED

#include "sentry_crash_artifacts.h"

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#define SENTRY__WIDEN2(value) L##value
#define SENTRY__WIDEN(value) SENTRY__WIDEN2(value)

#define SENTRY_WER_MAX_PATH 32768

// Staged runtime context written by the app process and read by
// sentry_wer_module.dll via ReadProcessMemory when WerFault.exe invokes the WER
// callback. The pointer to this struct is passed as the `ctx` argument to
// WerRegisterRuntimeExceptionModule.
struct sentry_wer_runtime_context {
    uint32_t version;
    uint32_t size;
    uint32_t flags;
    wchar_t run_path[SENTRY_WER_MAX_PATH];
    wchar_t database_path[SENTRY_WER_MAX_PATH];
    wchar_t minidump_url[1024];
    wchar_t proxy[SENTRY_WER_MAX_PATH];
    wchar_t user_agent[128];
};

// Only the first two fields are read initially to validate version and struct
// size before committing to a full ReadProcessMemory of the complete context.
struct sentry_wer_runtime_context_header {
    uint32_t version;
    uint32_t size;
};

#define SENTRY_WER_RUNTIME_CONTEXT_VERSION 2u

#define SENTRY_WER_EVENT_FILE_W SENTRY__WIDEN(SENTRY_CRASH_EVENT_FILE)
#define SENTRY_WER_BREADCRUMB1_FILE_W                                          \
    SENTRY__WIDEN(SENTRY_CRASH_BREADCRUMB1_FILE)
#define SENTRY_WER_BREADCRUMB2_FILE_W                                          \
    SENTRY__WIDEN(SENTRY_CRASH_BREADCRUMB2_FILE)
#define SENTRY_WER_ATTACHMENTS_FILE_W                                          \
    SENTRY__WIDEN(SENTRY_CRASH_ATTACHMENTS_FILE)
#define SENTRY_WER_LAST_CRASH_FILE_W SENTRY__WIDEN(SENTRY_CRASH_LAST_CRASH_FILE)

#define SENTRY_WER_EVENT_FILE_A SENTRY_CRASH_EVENT_FILE
#define SENTRY_WER_BREADCRUMB1_FILE_A SENTRY_CRASH_BREADCRUMB1_FILE
#define SENTRY_WER_BREADCRUMB2_FILE_A SENTRY_CRASH_BREADCRUMB2_FILE
#define SENTRY_WER_ATTACHMENTS_FILE_A SENTRY_CRASH_ATTACHMENTS_FILE
#define SENTRY_WER_LAST_CRASH_FILE_A SENTRY_CRASH_LAST_CRASH_FILE

#define SENTRY_WER_MP_EVENT_PART SENTRY_CRASH_EVENT_PART
#define SENTRY_WER_MP_BREADCRUMB1_PART SENTRY_CRASH_BREADCRUMB1_PART
#define SENTRY_WER_MP_BREADCRUMB2_PART SENTRY_CRASH_BREADCRUMB2_PART
#define SENTRY_WER_MP_MINIDUMP_PART SENTRY_CRASH_MINIDUMP_PART

#define SENTRY_WER_MINIDUMP_FILE_W L"minidump.dmp"

#define SENTRY_WER_UPLOADED_MARKER_FILE_W L"__sentry-wer-uploaded"
#define SENTRY_WER_UPLOADED_MARKER_FILE_A "__sentry-wer-uploaded"

#define SENTRY_WER_STOWED_STACK_FILE_W L"__sentry-stowed-stack.txt"
#define SENTRY_WER_STOWED_STACK_FILE_A "__sentry-stowed-stack.txt"
#define SENTRY_WER_MP_STOWED_STACK_PART "__sentry-stowed-stack"

#define SENTRY_WER_FLAG_REQUIRE_CONSENT 0x00000001u

// Minimum valid size: version, size, and flags must all be present.
static const size_t SENTRY_WER_RUNTIME_CONTEXT_MIN_SIZE
    = offsetof(struct sentry_wer_runtime_context, flags)
    + sizeof(((struct sentry_wer_runtime_context *)0)->flags);

// ---------------------------------------------------------------------------
// ABI stability assertions
//
// sentry_wer_runtime_context is a shared-memory contract between the app
// process (sentry_backend_wer.cpp) and sentry_wer_module.dll running inside
// WerFault.exe.  The WER module reads the struct via ReadProcessMemory and
// validates the version/size header before accessing individual fields.  The
// version check accommodates future growth but only if fields are appended at
// the end; inserting or reordering fields silently breaks the cross-process
// read.
//
// These static_asserts pin every field at its expected byte offset.  Any
// structural change that shifts an existing field will fail to compile,
// forcing the author to bump SENTRY_WER_RUNTIME_CONTEXT_VERSION and update
// the offsets below intentionally.
// ---------------------------------------------------------------------------
#ifdef __cplusplus

static_assert(offsetof(sentry_wer_runtime_context, version) == 0,
    "version must be the first field");
static_assert(offsetof(sentry_wer_runtime_context, size) == sizeof(uint32_t),
    "size field offset changed");
static_assert(
    offsetof(sentry_wer_runtime_context, flags) == 2 * sizeof(uint32_t),
    "flags field offset changed");
static_assert(
    offsetof(sentry_wer_runtime_context, run_path) == 3 * sizeof(uint32_t),
    "run_path field offset changed");
static_assert(offsetof(sentry_wer_runtime_context, database_path)
        == 3 * sizeof(uint32_t) + sizeof(wchar_t) * SENTRY_WER_MAX_PATH,
    "database_path field offset changed");
static_assert(offsetof(sentry_wer_runtime_context, minidump_url)
        == 3 * sizeof(uint32_t) + 2 * sizeof(wchar_t) * SENTRY_WER_MAX_PATH,
    "minidump_url field offset changed");
static_assert(offsetof(sentry_wer_runtime_context, proxy)
        == 3 * sizeof(uint32_t) + 2 * sizeof(wchar_t) * SENTRY_WER_MAX_PATH
            + sizeof(wchar_t) * 1024,
    "proxy field offset changed");
static_assert(offsetof(sentry_wer_runtime_context, user_agent)
        == 3 * sizeof(uint32_t) + 3 * sizeof(wchar_t) * SENTRY_WER_MAX_PATH
            + sizeof(wchar_t) * 1024,
    "user_agent field offset changed");

#endif /* __cplusplus */

#endif
