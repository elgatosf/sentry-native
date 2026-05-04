#include "sentry_wer_stowed.h"

#include <cstdarg>

static bool
sentry_stowed_is_valid_signature(ULONG signature)
{
    return signature == SENTRY_WER_STOWED_SIGNATURE_V1
        || signature == SENTRY_WER_STOWED_SIGNATURE_V2;
}

static void
sentry_stowed_fourcc_to_string(ULONG value, char out[5])
{
    out[0] = (char)(value & 0xFF);
    out[1] = (char)((value >> 8) & 0xFF);
    out[2] = (char)((value >> 16) & 0xFF);
    out[3] = (char)((value >> 24) & 0xFF);
    out[4] = '\0';

    for (int i = 0; i < 4; ++i) {
        if ((unsigned char)out[i] < 0x20 || (unsigned char)out[i] > 0x7E) {
            strcpy_s(out, 5, "????");
            return;
        }
    }
}

static bool
sentry_stowed_write_line(HANDLE file, const char *fmt, ...)
{
    char line[768];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf_s(line, sizeof(line), _TRUNCATE, fmt, args);
    va_end(args);

    if (len < 0) {
        len = (int)strnlen_s(line, sizeof(line));
    }
    if (len < 0 || (size_t)len + 2 >= sizeof(line)) {
        return false;
    }

    line[len++] = '\r';
    line[len++] = '\n';
    DWORD written = 0;
    return WriteFile(file, line, (DWORD)len, &written, nullptr)
        && written == (DWORD)len;
}

static const char *
sentry_stowed_signature_name(ULONG signature)
{
    if (signature == SENTRY_WER_STOWED_SIGNATURE_V1) {
        return "SE01";
    }
    if (signature == SENTRY_WER_STOWED_SIGNATURE_V2) {
        return "SE02";
    }
    return "unknown";
}

static const char *
sentry_stowed_form_name(DWORD form)
{
    if (form == SENTRY_WER_STOWED_FORM_BINARY) {
        return "binary";
    }
    if (form == SENTRY_WER_STOWED_FORM_TEXT) {
        return "text";
    }
    return "unknown";
}

static bool
sentry_stowed_resolve_address(HANDLE process, unsigned __int64 address,
    char *module_out, size_t module_cap, unsigned __int64 *base_out,
    DWORD *type_out, DWORD *protect_out)
{
    if (!process || !address || !module_out || !module_cap) {
        return false;
    }

    module_out[0] = '\0';
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(
            process, (LPCVOID)(ULONG_PTR)address, &mbi, sizeof(mbi))) {
        return false;
    }

    unsigned __int64 module_base
        = (unsigned __int64)(ULONG_PTR)mbi.AllocationBase;
    if (base_out) {
        *base_out = module_base;
    }
    if (type_out) {
        *type_out = mbi.Type;
    }
    if (protect_out) {
        *protect_out = mbi.Protect;
    }

    wchar_t full_path[MAX_PATH];
    full_path[0] = L'\0';
    DWORD chars = GetMappedFileNameW(process, (LPVOID)(ULONG_PTR)module_base,
        full_path, (DWORD)_countof(full_path));
    const wchar_t *basename = nullptr;
    if (chars) {
        basename = full_path;
        for (const wchar_t *cursor = full_path; *cursor; ++cursor) {
            if (*cursor == L'\\' || *cursor == L'/') {
                basename = cursor + 1;
            }
        }
    }
    if (!basename || !basename[0]) {
        strcpy_s(module_out, module_cap, "?");
        return true;
    }

    if (!WideCharToMultiByte(CP_UTF8, 0, basename, -1, module_out,
            (int)module_cap, nullptr, nullptr)) {
        strcpy_s(module_out, module_cap, "?");
    }
    return true;
}

static bool
sentry_stowed_read_stack_word(HANDLE process,
    const sentry_stowed_exception_information_v2 &info, unsigned index,
    unsigned __int64 *out)
{
    if (!out || info.form.bits.exception_form != SENTRY_WER_STOWED_FORM_BINARY) {
        return false;
    }

    ULONG word_size = info.payload.binary.stack_trace_word_size;
    ULONG word_count = info.payload.binary.stack_trace_words;
    PVOID stack_ptr = info.payload.binary.stack_trace;
    if (!process || !word_size || index >= word_count || !stack_ptr) {
        return false;
    }

    BYTE buffer[sizeof(unsigned __int64)] = { };
    SIZE_T to_read = word_size;
    if (to_read > sizeof(buffer)) {
        to_read = sizeof(buffer);
    }

    SIZE_T bytes_read = 0;
    const BYTE *address = (const BYTE *)stack_ptr + ((SIZE_T)index * word_size);
    if (!ReadProcessMemory(process, address, buffer, to_read, &bytes_read)
        || bytes_read != to_read) {
        return false;
    }

    unsigned __int64 value = 0;
    memcpy(&value, buffer, to_read);
    *out = value;
    return true;
}

static bool
sentry_stowed_read_grouping_address(HANDLE process,
    const sentry_stowed_exception_information_v2 &info, unsigned __int64 *out)
{
    if (!out || info.form.bits.exception_form != SENTRY_WER_STOWED_FORM_BINARY) {
        return false;
    }

    if (info.payload.binary.stack_trace_words > 1
        && sentry_stowed_read_stack_word(process, info, 1, out)) {
        return true;
    }
    return sentry_stowed_read_stack_word(process, info, 0, out);
}

static void
sentry_stowed_append_fingerprint(char *fingerprint, size_t fingerprint_len,
    HANDLE process, unsigned index,
    const sentry_stowed_exception_information_v2 &info)
{
    if (!fingerprint || !fingerprint_len) {
        return;
    }

    char nested[5];
    sentry_stowed_fourcc_to_string(info.nested_exception_type, nested);
    unsigned __int64 grouping_address = 0;
    sentry_stowed_read_grouping_address(process, info, &grouping_address);

    char part[160];
    _snprintf_s(part, _countof(part), _TRUNCATE,
        "stowed%u:0x%08lx:%s:0x%016I64x", index,
        (unsigned long)(ULONG)info.result_code, nested, grouping_address);

    if (fingerprint[0]) {
        strncat_s(fingerprint, fingerprint_len, "|", _TRUNCATE);
    }
    strncat_s(fingerprint, fingerprint_len, part, _TRUNCATE);
}

static bool
sentry_stowed_write_memory_preview(
    HANDLE file, HANDLE process, ULONG_PTR address)
{
    if (!address) {
        return true;
    }

    BYTE buffer[SENTRY_WER_NESTED_PREVIEW_LIMIT] = { };
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(process, (LPCVOID)address, buffer, sizeof(buffer),
            &bytes_read)
        || !bytes_read) {
        return sentry_stowed_write_line(file,
            "    Raw preview: unavailable (ReadProcessMemory failed)");
    }

    if (!sentry_stowed_write_line(file, "    Raw preview (%Iu bytes):",
            (unsigned __int64)bytes_read)) {
        return false;
    }

    for (SIZE_T offset = 0; offset < bytes_read; offset += 16) {
        unsigned __int64 first = 0;
        unsigned __int64 second = 0;
        SIZE_T first_len = bytes_read - offset;
        if (first_len > sizeof(first)) {
            first_len = sizeof(first);
        }
        memcpy(&first, buffer + offset, first_len);
        if (offset + sizeof(first) < bytes_read) {
            SIZE_T second_len = bytes_read - offset - sizeof(first);
            if (second_len > sizeof(second)) {
                second_len = sizeof(second);
            }
            memcpy(&second, buffer + offset + sizeof(first), second_len);
        }

        if (!sentry_stowed_write_line(file,
                "      +0x%04Ix: 0x%016I64x 0x%016I64x",
                (unsigned __int64)offset, first, second)) {
            return false;
        }
    }
    return true;
}

bool
sentry_stowed_load_pointer_array(
    const EXCEPTION_RECORD &record, sentry_stowed_pointer_array *out)
{
    if (!out || !is_stowed_exception_code(record.ExceptionCode)) {
        return false;
    }

    ZeroMemory(out, sizeof(*out));
    // ExceptionInformation[0]: base address of the ULONG_PTR[] array of
    // stowed-exception-info pointers in the crashing process.
    // ExceptionInformation[1]: low 32 bits are the array element count.
    if (record.NumberParameters >= 1) {
        out->base = (ULONG_PTR)record.ExceptionInformation[0];
    }
    if (record.NumberParameters >= 2) {
        out->count = (ULONG)(record.ExceptionInformation[1] & ULONG_MAX);
    }
    return out->base != 0;
}

bool
sentry_stowed_describe_remote_range(HANDLE process, ULONG_PTR address,
    SIZE_T limit, sentry_minidump_memory_range *range)
{
    if (!process || !address || !range) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(process, (LPCVOID)address, &mbi, sizeof(mbi))) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    SIZE_T offset
        = (SIZE_T)((const BYTE *)address - (const BYTE *)mbi.BaseAddress);
    if (offset >= mbi.RegionSize) {
        return false;
    }

    SIZE_T available = mbi.RegionSize - offset;
    SIZE_T to_copy = available;
    if (limit && to_copy > limit) {
        to_copy = limit;
    }
    if (!to_copy || to_copy > ULONG_MAX) {
        return false;
    }

    range->base = (ULONG64)address;
    range->size = (ULONG)to_copy;
    return true;
}

bool
sentry_stowed_append_memory_range(sentry_minidump_memory_range *ranges,
    size_t *count, size_t max_ranges,
    const sentry_minidump_memory_range *candidate)
{
    if (!ranges || !count || !candidate) {
        return false;
    }

    for (size_t i = 0; i < *count; ++i) {
        if (ranges[i].base == candidate->base) {
            if (candidate->size > ranges[i].size) {
                ranges[i] = *candidate;
            }
            return true;
        }
    }

    if (*count >= max_ranges) {
        return false;
    }

    ranges[*count] = *candidate;
    (*count)++;
    return true;
}

bool
sentry_stowed_write_stack_text(const wchar_t *path, HANDLE process,
    const sentry_stowed_exception_information_v2 &info)
{
    if (!path || !path[0] || !process) {
        return false;
    }

    sentry_unique_handle file(CreateFileW(path, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }

    bool ok = true;
    ok = sentry_stowed_write_line(file.get(),
        "Stowed Exception @ inline")
        && sentry_stowed_write_line(file.get(), "  ResultCode: 0x%08lx",
            (unsigned long)(ULONG)info.result_code)
        && sentry_stowed_write_line(file.get(), "  Form: %s (%lu)",
            sentry_stowed_form_name(info.form.bits.exception_form),
            (unsigned long)info.form.bits.exception_form);

    if (ok && info.form.bits.exception_form == SENTRY_WER_STOWED_FORM_BINARY) {
        ULONG word_size = info.payload.binary.stack_trace_word_size;
        ULONG word_count = info.payload.binary.stack_trace_words;
        PVOID stack_ptr = info.payload.binary.stack_trace;
        ok = sentry_stowed_write_line(file.get(),
            "  StackTrace: %p words=%lu word_size=%lu", stack_ptr,
            (unsigned long)word_count, (unsigned long)word_size);
        for (ULONG i = 0; ok && i < word_count && i < 64; ++i) {
            unsigned __int64 value = 0;
            if (!sentry_stowed_read_stack_word(process, info, i, &value)) {
                ok = sentry_stowed_write_line(
                    file.get(), "    #%02lu <unreadable>", (unsigned long)i);
                continue;
            }

            char module_name[120];
            unsigned __int64 module_base = 0;
            DWORD type = 0;
            DWORD protect = 0;
            if (!sentry_stowed_resolve_address(process, value, module_name,
                    sizeof(module_name), &module_base, &type, &protect)) {
                strcpy_s(module_name, "?");
            }

            unsigned __int64 delta = module_base && value >= module_base
                ? value - module_base
                : 0;
            ok = sentry_stowed_write_line(file.get(),
                "    #%02lu %s+0x%I64x (0x%016I64x) type=0x%lx protect=0x%lx",
                (unsigned long)i, module_name, delta, value,
                (unsigned long)type, (unsigned long)protect);
        }

        if (ok && word_count > 64) {
            ok = sentry_stowed_write_line(
                file.get(), "    ... %lu more stack words omitted",
                (unsigned long)(word_count - 64));
        }
    }

    if (ok) {
        static const char footer[] = "#-- end --\r\n";
        DWORD footer_len = (DWORD)(sizeof(footer) - 1);
        DWORD written_out = 0;
        if (!WriteFile(file.get(), footer, footer_len, &written_out, nullptr)
            || written_out != footer_len) {
            ok = false;
        }
    }

    if (!ok) {
        DeleteFileW(path);
    }
    return ok;
}

bool
sentry_stowed_read_exception(HANDLE process, ULONG_PTR address,
    sentry_stowed_exception_information_v2 *out, sentry_stowed_log_fn log_fn)
{
    // Two attempts: first read the blob directly, then follow one level of
    // pointer indirection. Some WinRT versions store a pointer-to-pointer.
    // The field-swap correction handles the case where the OS writes size
    // before signature in memory (observed on some Windows builds).
    if (!process || !address || !out) {
        return false;
    }

    ULONG_PTR current = address;
    for (int attempt = 0; attempt < 2; ++attempt) {
        SIZE_T bytes_read = 0;
        sentry_stowed_exception_information_v2 info = { };
        if (!ReadProcessMemory(
                process, (LPCVOID)current, &info, sizeof(info), &bytes_read)) {
            if (log_fn) {
                log_fn(L"ReadProcessMemory stowed failed addr=%p err=%lu",
                    (void *)current, GetLastError());
            }
            return false;
        }

        if (bytes_read < sizeof(sentry_stowed_exception_information_header)
            || info.header.size
                < sizeof(sentry_stowed_exception_information_header)) {
            if (log_fn) {
                log_fn(L"Stowed header too small rd=%Iu size=%lu",
                    (unsigned __int64)bytes_read, info.header.size);
            }
            return false;
        }

        if (!sentry_stowed_is_valid_signature(info.header.signature)
            && sentry_stowed_is_valid_signature(info.header.size)) {
            if (log_fn) {
                log_fn(L"Stowed header fields swapped; correcting "
                       L"(sig=0x%08lx size=%lu)",
                    info.header.signature, info.header.size);
            }
            ULONG tmp = info.header.signature;
            info.header.signature = info.header.size;
            info.header.size = tmp;
        }

        if (sentry_stowed_is_valid_signature(info.header.signature)) {
            if (log_fn) {
                log_fn(L"Stowed blob signature=0x%08lx size=%lu @%p",
                    info.header.signature, info.header.size, (void *)current);
            }
            *out = info;
            return true;
        }

        ULONG_PTR indirect = 0;
        SIZE_T ptr_read = 0;
        if (!ReadProcessMemory(process, (LPCVOID)current, &indirect,
                sizeof(indirect), &ptr_read)
            || ptr_read != sizeof(indirect) || !indirect
            || indirect == current) {
            if (log_fn) {
                log_fn(
                    L"Unexpected stowed signature=0x%08lx and no indirection",
                    info.header.signature);
            }
            return false;
        }

        if (log_fn) {
            log_fn(L"Stowed blob pointer indirection %p -> %p", (void *)current,
                (void *)indirect);
        }
        current = indirect;
    }

    return false;
}

static bool
sentry_stowed_write_stack_section(HANDLE file, HANDLE process,
    const sentry_stowed_exception_information_v2 &info, const char *indent)
{
    ULONG word_size = info.payload.binary.stack_trace_word_size;
    ULONG word_count = info.payload.binary.stack_trace_words;
    PVOID stack_ptr = info.payload.binary.stack_trace;
    if (!word_size || !word_count || !stack_ptr) {
        return sentry_stowed_write_line(file,
            "%sStackTrace: unavailable words=%lu word_size=%lu ptr=%p", indent,
            (unsigned long)word_count, (unsigned long)word_size, stack_ptr);
    }

    if (!sentry_stowed_write_line(file,
            "%sStackTrace: %p words=%lu word_size=%lu", indent, stack_ptr,
            (unsigned long)word_count, (unsigned long)word_size)) {
        return false;
    }

    for (ULONG i = 0; i < word_count && i < 64; ++i) {
        unsigned __int64 value = 0;
        if (!sentry_stowed_read_stack_word(process, info, i, &value)) {
            if (!sentry_stowed_write_line(
                    file, "%s  #%02lu <unreadable>", indent, (unsigned long)i)) {
                return false;
            }
            continue;
        }

        char module_name[120];
        unsigned __int64 module_base = 0;
        DWORD type = 0;
        DWORD protect = 0;
        if (!sentry_stowed_resolve_address(process, value, module_name,
                sizeof(module_name), &module_base, &type, &protect)) {
            strcpy_s(module_name, "?");
        }

        unsigned __int64 delta = module_base && value >= module_base
            ? value - module_base
            : 0;
        if (!sentry_stowed_write_line(file,
                "%s  #%02lu %s+0x%I64x (0x%016I64x) type=0x%lx protect=0x%lx",
                indent, (unsigned long)i, module_name, delta, value,
                (unsigned long)type, (unsigned long)protect)) {
            return false;
        }
    }

    if (word_count > 64) {
        return sentry_stowed_write_line(file,
            "%s  ... %lu more stack words omitted", indent,
            (unsigned long)(word_count - 64));
    }
    return true;
}

static bool
sentry_stowed_write_exception_report(HANDLE file, HANDLE process,
    ULONG_PTR address, const sentry_stowed_exception_information_v2 &info,
    size_t depth)
{
    const char *indent = depth ? "    " : "  ";
    char nested[5];
    sentry_stowed_fourcc_to_string(info.nested_exception_type, nested);

    if (!sentry_stowed_write_line(file, "%sAddress: %p", indent,
            (void *)address)
        || !sentry_stowed_write_line(file, "%sHeader: %s size=%lu", indent,
            sentry_stowed_signature_name(info.header.signature),
            (unsigned long)info.header.size)
        || !sentry_stowed_write_line(file, "%sResultCode: 0x%08lx", indent,
            (unsigned long)(ULONG)info.result_code)
        || !sentry_stowed_write_line(file, "%sForm: %s (%lu)", indent,
            sentry_stowed_form_name(info.form.bits.exception_form),
            (unsigned long)info.form.bits.exception_form)
        || !sentry_stowed_write_line(file, "%sThreadId: %lu", indent,
            (unsigned long)info.form.bits.thread_id)) {
        return false;
    }

    if (info.form.bits.exception_form == SENTRY_WER_STOWED_FORM_BINARY) {
        if (!sentry_stowed_write_line(file, "%sExceptionAddress: %p", indent,
                info.payload.binary.exception_address)
            || !sentry_stowed_write_stack_section(file, process, info, indent)) {
            return false;
        }
    } else if (info.form.bits.exception_form == SENTRY_WER_STOWED_FORM_TEXT) {
        if (!sentry_stowed_write_line(file, "%sErrorText: %p", indent,
                info.payload.text.error_text)) {
            return false;
        }
    }

    if (!sentry_stowed_write_line(file,
            "%sNestedExceptionType: %s (0x%08lx)", indent, nested,
            (unsigned long)info.nested_exception_type)
        || !sentry_stowed_write_line(file, "%sNestedException: %p", indent,
            info.nested_exception)) {
        return false;
    }

    if (!info.nested_exception) {
        return true;
    }

    sentry_stowed_exception_information_v2 nested_info = { };
    ULONG_PTR nested_address = (ULONG_PTR)info.nested_exception;
    if (depth + 1 < SENTRY_WER_STOWED_MAX_NESTING_DEPTH
        && sentry_stowed_read_exception(
            process, nested_address, &nested_info, nullptr)) {
        return sentry_stowed_write_line(file, "%sNested stowed exception:",
                   indent)
            && sentry_stowed_write_exception_report(
                file, process, nested_address, nested_info, depth + 1);
    }

    if (info.nested_exception_type == SENTRY_WER_NESTED_TYPE_LEO1) {
        unsigned __int64 clr_hint = 0;
        if (!sentry_stowed_write_line(file,
                "%sAssociated CLR exception: LEO1 language exception object.",
                indent)) {
            return false;
        }
        if (sentry_stowed_read_grouping_address(process, info, &clr_hint)
            && !sentry_stowed_write_line(file,
                "%sCLR stack hint address: 0x%016I64x", indent, clr_hint)) {
            return false;
        }
        if (!sentry_stowed_write_line(file,
                "%sCLR stack frames require CLR/SOS decoding; raw nested memory follows.",
                indent)
            || !sentry_stowed_write_line(file,
                "%sUse the minidump with !dse/!pe when full managed frames are needed.",
                indent)) {
            return false;
        }
    }

    return sentry_stowed_write_memory_preview(file, process, nested_address);
}

static bool
sentry_stowed_write_report_text(const wchar_t *path, HANDLE process,
    const ULONG_PTR *entry_ptrs,
    const sentry_stowed_exception_information_v2 *entries, const bool *have,
    ULONG count, const char *fingerprint)
{
    if (!path || !path[0] || !process || !entry_ptrs || !entries || !have) {
        return false;
    }

    sentry_unique_handle file(CreateFileW(path, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }

    bool ok = sentry_stowed_write_line(
        file.get(), "Stowed Exception Report")
        && sentry_stowed_write_line(file.get(), "Entries captured: %lu", count);
    if (ok && fingerprint && fingerprint[0]) {
        ok = sentry_stowed_write_line(
            file.get(), "Suggested fingerprint: %s", fingerprint);
    }
    if (ok) {
        ok = sentry_stowed_write_line(file.get(), "");
    }

    for (ULONG i = 0; ok && i < count; ++i) {
        ok = sentry_stowed_write_line(
            file.get(), "Stowed Exception #%lu", (unsigned long)(i + 1));
        if (!ok) {
            break;
        }
        if (!have[i]) {
            ok = sentry_stowed_write_line(file.get(), "  Address: %p",
                (void *)entry_ptrs[i])
                && sentry_stowed_write_line(file.get(), "  <unreadable>");
            continue;
        }
        ok = sentry_stowed_write_exception_report(
            file.get(), process, entry_ptrs[i], entries[i], 0)
            && sentry_stowed_write_line(file.get(), "");
    }

    if (ok) {
        ok = sentry_stowed_write_line(file.get(), "#-- end --");
    }

    if (!ok) {
        DeleteFileW(path);
    }
    return ok;
}

bool
sentry_stowed_add_pointer_range_if_valid(HANDLE process, ULONG_PTR address,
    SIZE_T limit, sentry_minidump_memory_range *ranges, size_t *count,
    size_t max_ranges, sentry_stowed_log_fn log_fn)
{
    if (!process || !address) {
        return false;
    }

    sentry_minidump_memory_range range = { };
    if (!sentry_stowed_describe_remote_range(process, address, limit, &range)) {
        if (log_fn) {
            log_fn(L"describe_remote_range failed addr=%p limit=%Iu",
                (void *)address, (unsigned __int64)limit);
        }
        return false;
    }

    if (!sentry_stowed_append_memory_range(ranges, count, max_ranges, &range)) {
        if (log_fn) {
            log_fn(L"append_memory_range failed base=0x%I64x size=%lu",
                range.base, range.size);
        }
        return false;
    }

    if (log_fn) {
        log_fn(L"Queued stowed range base=0x%I64x size=%lu", range.base,
            range.size);
    }
    return true;
}

static void
sentry_stowed_collect_exception_memory(HANDLE process,
    const sentry_stowed_exception_information_v2 &stowed,
    sentry_minidump_memory_range *ranges, size_t *added, size_t max_ranges,
    sentry_stowed_log_fn log_fn, size_t depth)
{
    if (stowed.form.bits.exception_form == SENTRY_WER_STOWED_FORM_BINARY) {
        if (stowed.payload.binary.exception_address) {
            sentry_stowed_add_pointer_range_if_valid(process,
                (ULONG_PTR)stowed.payload.binary.exception_address,
                SENTRY_WER_EXCEPTION_ADDR_LIMIT, ranges, added, max_ranges,
                log_fn);
        }

        ULONG word_size = stowed.payload.binary.stack_trace_word_size;
        ULONG word_count = stowed.payload.binary.stack_trace_words;
        PVOID stack_trace_ptr = stowed.payload.binary.stack_trace;
        if (word_size && word_count && stack_trace_ptr) {
            SIZE_T total_bytes = (SIZE_T)word_size * (SIZE_T)word_count;
            if (total_bytes > SENTRY_WER_STOWED_COPY_LIMIT) {
                total_bytes = SENTRY_WER_STOWED_COPY_LIMIT;
            }

            if (log_fn) {
                log_fn(L"Stack trace words=%lu word_size=%lu total_bytes=%Iu",
                    word_count, word_size, (unsigned __int64)total_bytes);
            }

            sentry_stowed_add_pointer_range_if_valid(process,
                (ULONG_PTR)stack_trace_ptr, total_bytes, ranges, added,
                max_ranges, log_fn);
        } else if (log_fn) {
            log_fn(L"Missing stack trace fields: words=%lu size=%lu ptr=%p",
                word_count, word_size, stack_trace_ptr);
        }
    } else if (stowed.form.bits.exception_form == SENTRY_WER_STOWED_FORM_TEXT) {
        if (stowed.payload.text.error_text) {
            sentry_stowed_add_pointer_range_if_valid(process,
                (ULONG_PTR)stowed.payload.text.error_text,
                SENTRY_WER_ERROR_TEXT_LIMIT, ranges, added, max_ranges, log_fn);
        } else if (log_fn) {
            log_fn(L"Text form missing error_text pointer");
        }
    } else if (log_fn) {
        log_fn(L"Unknown stowed exception form=%lu",
            (unsigned long)stowed.form.bits.exception_form);
    }

    if (!stowed.nested_exception) {
        return;
    }

    ULONG_PTR nested_address = (ULONG_PTR)stowed.nested_exception;
    sentry_stowed_add_pointer_range_if_valid(process, nested_address,
        SENTRY_WER_STOWED_COPY_LIMIT, ranges, added, max_ranges, log_fn);

    if (depth + 1 >= SENTRY_WER_STOWED_MAX_NESTING_DEPTH) {
        return;
    }

    sentry_stowed_exception_information_v2 nested = { };
    if (sentry_stowed_read_exception(process, nested_address, &nested, log_fn)) {
        sentry_stowed_collect_exception_memory(process, nested, ranges, added,
            max_ranges, log_fn, depth + 1);
    }
}

size_t
sentry_stowed_collect_memory_ranges(sentry_stowed_log_fn log_fn,
    const PWER_RUNTIME_EXCEPTION_INFORMATION info,
    sentry_minidump_memory_range *ranges, size_t max_ranges,
    const wchar_t *stack_text_path, char *fingerprint, size_t fingerprint_len)
{
    // Reads the stowed-exception pointer array from the crashed process,
    // resolves each entry's committed memory region via VirtualQueryEx,
    // and writes a text stack sidecar for binary-form entries.
    // Returns the number of memory ranges added to `ranges`.
    if (!info || !ranges || !max_ranges) {
        return 0;
    }
    if (fingerprint && fingerprint_len) {
        fingerprint[0] = '\0';
    }

    sentry_stowed_pointer_array array = { };
    if (!sentry_stowed_load_pointer_array(info->exceptionRecord, &array)) {
        return 0;
    }
    if (!array.count) {
        if (log_fn) {
            log_fn(L"Stowed pointer array empty base=%p", (void *)array.base);
        }
        return 0;
    }

    ULONG count = array.count;
    if (count > SENTRY_WER_STOWED_MAX_POINTERS) {
        count = (ULONG)SENTRY_WER_STOWED_MAX_POINTERS;
    }

    if (log_fn) {
        log_fn(L"Stowed pointer array base=%p count=%lu", (void *)array.base,
            array.count);
    }

    std::array<ULONG_PTR, SENTRY_WER_STOWED_MAX_POINTERS> entry_ptrs = { };
    SIZE_T expected = (SIZE_T)count * sizeof(ULONG_PTR);
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(info->hProcess, (LPCVOID)array.base,
            entry_ptrs.data(), expected, &bytes_read)
        || bytes_read < expected) {
        if (log_fn) {
            log_fn(L"ReadProcessMemory pointer array failed err=%lu bytes=%Iu",
                GetLastError(), (unsigned __int64)bytes_read);
        }
        return 0;
    }

    size_t added = 0;
    for (ULONG i = 0; i < count; ++i) {
        if (!entry_ptrs[i]) {
            continue;
        }
        sentry_stowed_add_pointer_range_if_valid(info->hProcess, entry_ptrs[i],
            SENTRY_WER_STOWED_COPY_LIMIT, ranges, &added, max_ranges, log_fn);
    }

    std::array<sentry_stowed_exception_information_v2,
        SENTRY_WER_STOWED_MAX_POINTERS>
        stowed_entries = { };
    std::array<bool, SENTRY_WER_STOWED_MAX_POINTERS> have_stowed = { };
    for (ULONG i = 0; i < count; ++i) {
        if (!entry_ptrs[i]) {
            continue;
        }

        have_stowed[i] = sentry_stowed_read_exception(
            info->hProcess, entry_ptrs[i], &stowed_entries[i], log_fn);
        if (!have_stowed[i]) {
            if (log_fn) {
                log_fn(L"Failed to read stowed blob at %p",
                    (void *)entry_ptrs[i]);
            }
            continue;
        }

        if (log_fn) {
            log_fn(L"Stowed exception #%lu form=%lu",
                (unsigned long)(i + 1),
                (unsigned long)stowed_entries[i].form.bits.exception_form);
        }

        sentry_stowed_append_fingerprint(fingerprint, fingerprint_len,
            info->hProcess, i + 1, stowed_entries[i]);
        sentry_stowed_collect_exception_memory(info->hProcess,
            stowed_entries[i], ranges, &added, max_ranges, log_fn, 0);
    }

    if (stack_text_path && stack_text_path[0]) {
        if (sentry_stowed_write_report_text(stack_text_path, info->hProcess,
                entry_ptrs.data(), stowed_entries.data(), have_stowed.data(),
                count, fingerprint)) {
            if (log_fn) {
                log_fn(L"Wrote stowed stack text: %ls", stack_text_path);
            }
        } else if (log_fn) {
            log_fn(L"Failed to write stowed stack text");
        }
    }

    if (log_fn) {
        log_fn(L"Total stowed ranges queued=%Iu", (unsigned __int64)added);
    }
    return added;
}
