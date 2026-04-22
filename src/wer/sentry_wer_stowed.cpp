#include "sentry_wer_stowed.h"

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
    // Output format (one line per word):
    //   #NN module_name+0xoffset (0xRRRRRRRR)
    // followed by "#-- end --" on the last line.
    // module_name is resolved via VirtualQueryEx + GetMappedFileNameW.
    if (!path || !path[0] || !process) {
        return false;
    }
    if (info.form.bits.exception_form != SENTRY_WER_STOWED_FORM_BINARY) {
        return false;
    }

    ULONG word_size = info.payload.binary.stack_trace_word_size;
    ULONG word_count = info.payload.binary.stack_trace_words;
    PVOID stack_ptr = info.payload.binary.stack_trace;
    if (!word_size || !word_count || !stack_ptr) {
        return false;
    }

    SIZE_T bytes_to_copy = (SIZE_T)word_size * (SIZE_T)word_count;
    if (!bytes_to_copy) {
        return false;
    }
    if (bytes_to_copy > SENTRY_WER_STOWED_COPY_LIMIT) {
        bytes_to_copy = SENTRY_WER_STOWED_COPY_LIMIT;
    }

    std::vector<BYTE> buffer(bytes_to_copy);
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(
            process, stack_ptr, buffer.data(), bytes_to_copy, &bytes_read)
        || bytes_read < word_size) {
        return false;
    }

    word_count = (ULONG)(bytes_read / word_size);
    if (!word_count) {
        return false;
    }

    sentry_unique_handle file(CreateFileW(path, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        return false;
    }

    struct sentry_stowed_module_name_entry {
        ULONG_PTR base;
        wchar_t name[MAX_PATH];
    };

    std::vector<sentry_stowed_module_name_entry> module_cache;
    auto resolve_module = [&](unsigned __int64 address, wchar_t *name_out,
                              size_t cap, unsigned __int64 *base_out) {
        if (!address) {
            return false;
        }

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

        for (const auto &entry : module_cache) {
            if (entry.base == module_base) {
                wcsncpy_s(name_out, cap, entry.name, _TRUNCATE);
                return true;
            }
        }

        wchar_t full_path[MAX_PATH];
        full_path[0] = L'\0';
        DWORD chars
            = GetMappedFileNameW(process, (LPVOID)(ULONG_PTR)module_base,
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
            basename = L"?";
        }

        sentry_stowed_module_name_entry entry = { };
        entry.base = (ULONG_PTR)module_base;
        wcsncpy_s(entry.name, _countof(entry.name), basename, _TRUNCATE);
        module_cache.push_back(entry);
        wcsncpy_s(name_out, cap, entry.name, _TRUNCATE);
        return true;
    };

    bool ok = true;
    char line[160];
    for (ULONG i = 0; i < word_count && ok; ++i) {
        unsigned __int64 value = 0;
        SIZE_T to_copy = word_size;
        if (to_copy > sizeof(value)) {
            to_copy = sizeof(value);
        }

        memcpy(
            &value, buffer.data() + ((SIZE_T)i * (SIZE_T)word_size), to_copy);

        int hex_width = (int)(word_size * 2);
        if (hex_width > 16) {
            hex_width = 16;
        }

        wchar_t module_name_w[MAX_PATH];
        module_name_w[0] = L'\0';
        unsigned __int64 module_base = 0;
        if (!resolve_module(
                value, module_name_w, _countof(module_name_w), &module_base)) {
            wcscpy_s(module_name_w, _countof(module_name_w), L"?");
        }

        unsigned __int64 delta = 0;
        if (module_base && value >= module_base) {
            delta = value - module_base;
        }

        char module_name_a[120];
        if (!WideCharToMultiByte(CP_UTF8, 0, module_name_w, -1, module_name_a,
                (int)sizeof(module_name_a), nullptr, nullptr)) {
            strcpy_s(module_name_a, "?");
        }

        int written
            = _snprintf_s(line, _TRUNCATE, "#%02lu %s+0x%I64x (0x%0*I64x)\r\n",
                (unsigned long)i, module_name_a, delta, hex_width, value);
        if (written <= 0) {
            ok = false;
            break;
        }

        DWORD line_len = (DWORD)written;
        DWORD written_out = 0;
        if (!WriteFile(file.get(), line, line_len, &written_out, nullptr)
            || written_out != line_len) {
            ok = false;
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

    auto is_valid_sig = [](ULONG signature) {
        return signature == SENTRY_WER_STOWED_SIGNATURE_V1
            || signature == SENTRY_WER_STOWED_SIGNATURE_V2;
    };

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

        if (!is_valid_sig(info.header.signature)
            && is_valid_sig(info.header.size)) {
            if (log_fn) {
                log_fn(L"Stowed header fields swapped; correcting "
                       L"(sig=0x%08lx size=%lu)",
                    info.header.signature, info.header.size);
            }
            ULONG tmp = info.header.signature;
            info.header.signature = info.header.size;
            info.header.size = tmp;
        }

        if (is_valid_sig(info.header.signature)) {
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

size_t
sentry_stowed_collect_memory_ranges(sentry_stowed_log_fn log_fn,
    const PWER_RUNTIME_EXCEPTION_INFORMATION info,
    sentry_minidump_memory_range *ranges, size_t max_ranges,
    const wchar_t *stack_text_path)
{
    // Reads the stowed-exception pointer array from the crashed process,
    // resolves each entry's committed memory region via VirtualQueryEx,
    // and writes a text stack sidecar for binary-form entries.
    // Returns the number of memory ranges added to `ranges`.
    if (!info || !ranges || !max_ranges) {
        return 0;
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

    sentry_stowed_exception_information_v2 stowed = { };
    bool have_stowed = entry_ptrs[0]
        && sentry_stowed_read_exception(
            info->hProcess, entry_ptrs[0], &stowed, log_fn);
    if (!have_stowed && entry_ptrs[0] && log_fn) {
        log_fn(L"Failed to read stowed blob at %p", (void *)entry_ptrs[0]);
    }

    if (have_stowed) {
        DWORD form = stowed.form.bits.exception_form;
        if (log_fn) {
            log_fn(L"Stowed exception form=%lu", (unsigned long)form);
        }

        if (form == SENTRY_WER_STOWED_FORM_BINARY) {
            if (stack_text_path && stack_text_path[0]) {
                if (sentry_stowed_write_stack_text(
                        stack_text_path, info->hProcess, stowed)) {
                    if (log_fn) {
                        log_fn(
                            L"Wrote stowed stack text: %ls", stack_text_path);
                    }
                } else if (log_fn) {
                    log_fn(L"Failed to write stowed stack text");
                }
            }

            if (stowed.payload.binary.exception_address) {
                sentry_stowed_add_pointer_range_if_valid(info->hProcess,
                    (ULONG_PTR)stowed.payload.binary.exception_address,
                    SENTRY_WER_EXCEPTION_ADDR_LIMIT, ranges, &added, max_ranges,
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
                    log_fn(
                        L"Stack trace words=%lu word_size=%lu total_bytes=%Iu",
                        word_count, word_size, (unsigned __int64)total_bytes);
                }

                sentry_stowed_add_pointer_range_if_valid(info->hProcess,
                    (ULONG_PTR)stack_trace_ptr, total_bytes, ranges, &added,
                    max_ranges, log_fn);
            } else if (log_fn) {
                log_fn(L"Missing stack trace fields: words=%lu size=%lu ptr=%p",
                    word_count, word_size, stack_trace_ptr);
            }
        } else if (form == SENTRY_WER_STOWED_FORM_TEXT) {
            if (stowed.payload.text.error_text) {
                sentry_stowed_add_pointer_range_if_valid(info->hProcess,
                    (ULONG_PTR)stowed.payload.text.error_text,
                    SENTRY_WER_ERROR_TEXT_LIMIT, ranges, &added, max_ranges,
                    log_fn);
            } else if (log_fn) {
                log_fn(L"Text form missing error_text pointer");
            }
        } else if (log_fn) {
            log_fn(L"Unknown stowed exception form=%lu", (unsigned long)form);
        }

        if (stowed.nested_exception) {
            sentry_stowed_add_pointer_range_if_valid(info->hProcess,
                (ULONG_PTR)stowed.nested_exception,
                SENTRY_WER_STOWED_COPY_LIMIT, ranges, &added, max_ranges,
                log_fn);
        }
    }

    if (log_fn) {
        log_fn(L"Total stowed ranges queued=%Iu", (unsigned __int64)added);
    }
    return added;
}
