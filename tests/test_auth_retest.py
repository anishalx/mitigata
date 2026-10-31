"""Authentication across resumed runs: the per-account cap survives a restart, and only new literals are tried."""

from __future__ import annotations

import json

from mitigata.pipeline import verifier

BASIC = {"class": "default_credentials", "surface": "basic_auth", "ip": "192.168.60.139", "port": 1111, "target": "/"}
PASSKEY = {"class": "passkey_protocol_auth", "ip": "192.168.60.139", "port": 8833}


def test_control_key_matches_the_account_the_checks_charge():
    assert verifier.surface_control_key(BASIC) == "basic:192.168.60.139:1111/:admin"
    assert verifier.surface_control_key(PASSKEY) == "passkey:192.168.60.139:8833"


def test_resumed_run_rebuilds_attempts_tried_refs_blocks_and_accepted_literals():
    rows = [
        # written before per-account accounting existed: six attempts, defaults only
        {"id": 1, "type": "verification", "candidate_id": 16, "payload_json": json.dumps({"attempts": 6})},
        {"id": 2, "type": "verification", "candidate_id": 16, "payload_json": json.dumps({
            "tried_refs": ["cred-1"], "accounts": {"basic:192.168.60.139:1111/:elastic": 1},
            "blocked_accounts": ["basic:192.168.60.139:1111/:root"], "accepted_refs": []})},
        {"id": 3, "type": "verification", "candidate_id": 20, "payload_json": json.dumps({"accepted_refs": ["cred-9"]})},
        {"id": 4, "type": "evidence", "candidate_id": 16, "payload_json": "{}"},
    ]
    prior = verifier.prior_auth_state(rows, {16: BASIC})
    assert prior.used == {"basic:192.168.60.139:1111/:admin": 6, "basic:192.168.60.139:1111/:elastic": 1}
    assert prior.tried[16] == {"", "cred-1"}
    assert prior.blocked == {"basic:192.168.60.139:1111/:root"}
    assert prior.accepted == {"cred-9": (20, 3)}


def test_retest_plan_tries_only_new_literals_and_never_repeats_defaults():
    prior = verifier.PriorAuth(tried={16: {""}, 12: set(), 9: {"", "cred-1"}})
    candidates = [
        (16, "default_credentials", "rejected", BASIC),                                  # defaults done, literal new
        (12, "passkey_protocol_auth", "inconclusive", PASSKEY),                          # never attempted
        (9, "default_credentials", "rejected", {**BASIC, "port": 22}),                   # everything already tried
        (7, "default_credentials", "confirmed", BASIC),                                  # confirmed: not retested
        (1, "default_credentials", "inconclusive", {**BASIC, "ip": "192.168.60.16"}),    # outside the auth hosts
    ]
    plans = verifier.plan_auth_tests(candidates, prior, ["cred-1"], {"192.168.60.139"})
    assert set(plans) == {16, 12}
    assert plans[16].include_defaults is False and plans[16].only_refs == {"cred-1"}
    assert plans[12].only_refs == {"cred-1"}


def test_literal_only_pass_skips_default_pairs_and_keeps_the_pair_user():
    ctx = verifier.VerifyContext(
        guard=None, budget=verifier.AttemptBudget(cap=8, enabled=True),  # type: ignore[arg-type]
        secrets={"cred-1": "not-a-real-secret-1", "cred-2": "not-a-real-secret-2"},
        literal_refs=["cred-1", "cred-2"], flag_patterns=[],
        literal_meta={"cred-1": {"keyword": "basic-auth", "score": 2.5, "source": "web", "user": "elastic"},
                      "cred-2": {"keyword": "password", "score": 1.0, "source": "binary"}},
        include_defaults=False, only_refs=frozenset({"cred-1"}),
    )
    assert verifier._pairs(ctx) == [("elastic", "not-a-real-secret-1", "cred-1")]


def test_seeded_budget_keeps_the_per_account_cap_across_resumed_passes():
    budget = verifier.AttemptBudget(cap=8, enabled=True, used={"basic:x:admin": 7})
    assert budget.take("basic:x:admin") is True
    assert budget.take("basic:x:admin") is False
    assert budget.take("basic:x:elastic") is True


def test_attempt_cap_does_not_record_unsent_credentials_as_tried(monkeypatch):
    from mitigata.pipeline.web_agent import Response

    monkeypatch.setattr(verifier, "_basic_get", lambda *args, **kwargs: Response(401, {}, b"denied", ""))
    ctx = verifier.VerifyContext(
        guard=None, budget=verifier.AttemptBudget(cap=1, enabled=True),  # type: ignore[arg-type]
        secrets={"cred-1": "example-secret"}, literal_refs=["cred-1"], flag_patterns=[],
        include_defaults=False, engagement_key=b"test-key",
    )
    verdict = verifier.verify_basic_auth("127.0.0.1", 8080, False, {"target": "/", "path": "/"}, ctx)
    # With one attempt left, a control and one candidate cannot both run, so nothing is sent at all.
    assert verdict.attempts == 0
    assert verdict.credential_fingerprints == []
    assert ctx.tried_log == []
