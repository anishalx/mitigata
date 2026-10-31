from __future__ import annotations

from mitigata import dedup


def test_keys_are_deterministic_and_prefixed_by_purpose():
    run = "run-1"
    assert dedup.port(run, "10.10.5.10", 22, "tcp") == dedup.port(run, "10.10.5.10", 22, "tcp")
    assert dedup.port(run, "10.10.5.10", 22, "tcp") != dedup.port(run, "10.10.5.10", 23, "tcp")
    # Different purposes must never collide even with identical arguments.
    keys = {
        dedup.port(run, "10.10.5.10", 22, "tcp"),
        dedup.endpoint(run, 1, "GET", "/a"),
        dedup.check(run, 1, 2, "web.sqli", "id"),
        dedup.candidate(run, 1, 2, 3, "sqli", "id"),
        dedup.binary_artifact(run, "a" * 64),
        dedup.decompiled_function(run, "a" * 64, 4198400),
        dedup.reachability(run, "a" * 64, 4198400, "addr"),
        dedup.credential_reuse(run, 4, 5),
    }
    assert len(keys) == 8


def test_binary_scoped_keys_match_the_design():
    run = "run-1"
    sha = "b" * 64
    # §3.4: decompile and reachability keys are scoped per function/target.
    assert dedup.decompiled_function(run, sha, 1) != dedup.decompiled_function(run, sha, 2)
    assert dedup.reachability(run, sha, 1, "addr") != dedup.reachability(run, sha, 1, "unconstrained_ip")
    # Credential reuse is per credential x service, so two services stay distinct.
    assert dedup.credential_reuse(run, 7, 1) != dedup.credential_reuse(run, 7, 2)


def test_keys_are_run_scoped():
    assert dedup.binary_artifact("run-a", "a" * 64) != dedup.binary_artifact("run-b", "a" * 64)
