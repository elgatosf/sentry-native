#ifndef SENTRY_WER_WINHTTP_H_INCLUDED
#define SENTRY_WER_WINHTTP_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winhttp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sentry_wer_winhttp_result_s {
    unsigned status_code;
    bool rate_limited;
} sentry_wer_winhttp_result_t;

HINTERNET sentry__wer_winhttp_open_session(
    const wchar_t *user_agent, const wchar_t *proxy_w);

int sentry__wer_winhttp_simple_post(HINTERNET session, const wchar_t *host,
    INTERNET_PORT port, bool secure, const wchar_t *path,
    const wchar_t *extra_headers, const unsigned char *body, size_t body_len,
    sentry_wer_winhttp_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
