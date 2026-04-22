import os
import sys
import time
from pathlib import Path

import psutil
import pytest

from . import Envelope, make_dsn, run
from .assertions import assert_event_meta, assert_minidump, assert_wer_upload


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="WER backend tests require Windows",
)


def wait_for_no_werfault(timeout=30.0, poll_interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        werfaults = [
            process
            for process in psutil.process_iter(["name"])
            if process.info["name"]
            and process.info["name"].lower() == "werfault.exe"
        ]
        if not werfaults:
            return True
        time.sleep(poll_interval)
    return False


def set_stale_mtime(path, stale_age_seconds):
    stale_time = time.time() - stale_age_seconds
    os.utime(path, (stale_time, stale_time))


# this test currently can't run on CI because the Windows-image doesn't properly support WER, if you want to run it
# locally, invoke pytest with the --with_wer option which is matched with this marker in the runtest setup
@pytest.mark.with_wer
@pytest.mark.parametrize(
    "run_args",
    [
        ["fastfail"],
    ],
)
def test_wer_crash_upload(cmake, httpserver, run_args):
    tmp_path = cmake(["sentry_example"], {"SENTRY_BACKEND": "wer"})

    env = dict(os.environ, SENTRY_DSN=make_dsn(httpserver))
    httpserver.expect_oneshot_request("/api/123456/minidump/").respond_with_data("OK")

    assert wait_for_no_werfault()

    with httpserver.wait(timeout=60) as waiting:
        run(
            tmp_path,
            "sentry_example",
            ["attachment", "attach-view-hierarchy", "overflow-breadcrumbs"]
            + run_args,
            expect_failure=True,
            env=env,
        )

    assert waiting.result
    assert len(httpserver.log) == 1
    assert_wer_upload(
        httpserver.log[0][0],
        expect_attachment=True,
        expect_view_hierarchy=True,
        expect_stowed_stack=False,
    )
    assert wait_for_no_werfault()


@pytest.mark.with_wer
def test_wer_replays_staged_run_on_next_startup(cmake, httpserver, unreachable_dsn):
    tmp_path = cmake(["sentry_example"], {"SENTRY_BACKEND": "wer"})
    env = dict(os.environ, SENTRY_DSN=unreachable_dsn)

    assert wait_for_no_werfault()

    run(
        tmp_path,
        "sentry_example",
        ["attachment", "attach-view-hierarchy", "overflow-breadcrumbs", "fastfail"],
        expect_failure=True,
        env=env,
    )

    assert wait_for_no_werfault()

    database_path = tmp_path / ".sentry-native"
    staged_run_dirs = [path for path in database_path.glob("*.run") if path.is_dir()]
    assert staged_run_dirs, "expected the failed WER upload to leave a staged run"
    assert any(any(run_dir.glob("*.dmp")) for run_dir in staged_run_dirs)

    httpserver.expect_oneshot_request("/api/123456/envelope/").respond_with_data("OK")
    env["SENTRY_DSN"] = make_dsn(httpserver)

    with httpserver.wait(timeout=30) as waiting:
        run(tmp_path, "sentry_example", ["flush", "no-setup"], env=env)

    assert waiting.result
    assert len(httpserver.log) == 1

    envelope = Envelope.deserialize(httpserver.log[0][0].get_data())
    assert_event_meta(envelope.get_event(), integration="wer")
    assert_minidump(envelope)


def test_wer_prunes_stale_orphan_runs(cmake):
    tmp_path = cmake(["sentry_example"], {"SENTRY_BACKEND": "wer"})
    database_path = tmp_path / ".sentry-native"
    stale_run = database_path / "stale-orphan.run"
    stale_lock = Path(f"{stale_run}.lock")

    stale_run.mkdir(parents=True, exist_ok=True)
    (stale_run / "leftover.txt").write_text("orphaned staged WER data", encoding="utf-8")
    stale_lock.write_text("", encoding="utf-8")

    stale_age_seconds = 8 * 24 * 60 * 60
    set_stale_mtime(stale_run / "leftover.txt", stale_age_seconds)
    set_stale_mtime(stale_lock, stale_age_seconds)
    set_stale_mtime(stale_run, stale_age_seconds)

    run(tmp_path, "sentry_example", ["no-setup"])

    assert not stale_run.exists()
    assert not stale_lock.exists()
