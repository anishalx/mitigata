"""The control-first checks never send an attempt they cannot follow up: fewer than two attempts left means none sent."""

from __future__ import annotations

from mitigata.pipeline import verifier


def _context(budget: verifier.AttemptBudget, refs: list[str]) -> verifier.VerifyContext:
    return verifier.VerifyContext(guard=None, budget=budget, secrets={ref: "candidate-value" for ref in refs},
                                  literal_refs=list(refs), flag_patterns=[])


def test_remaining_counts_down_and_is_zero_when_blocked_or_disabled():
    budget = verifier.AttemptBudget(cap=8, enabled=True, used={"acct": 7})
    assert budget.remaining("acct") == 1
    assert budget.remaining("other") == 8
    budget.blocked.add("acct")
    assert budget.remaining("acct") == 0
    assert verifier.AttemptBudget(cap=8, enabled=False).remaining("acct") == 0


def test_passkey_check_sends_nothing_with_one_attempt_left(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("an attempt was sent with only one left")

    monkeypatch.setattr(verifier, "_exchange", no_network)
    budget = verifier.AttemptBudget(cap=8, enabled=True, used={"passkey:127.0.0.1:8833": 7})
    verdict = verifier.verify_passkey("127.0.0.1", 8833, {"class": "passkey_protocol_auth"},
                                      _context(budget, ["cred-1"]))
    assert verdict.verdict == "inconclusive" and verdict.attempts == 0
    assert "no attempt was sent" in verdict.summary
    assert budget.used["passkey:127.0.0.1:8833"] == 7


def test_basic_auth_check_sends_nothing_with_one_attempt_left(monkeypatch):
    def no_request(*args, **kwargs):
        raise AssertionError("a request was sent with only one attempt left")

    monkeypatch.setattr(verifier, "_basic_get", no_request)
    budget = verifier.AttemptBudget(cap=8, enabled=True, used={"basic:127.0.0.1:1111/:admin": 7})
    candidate = {"class": "default_credentials", "surface": "basic_auth", "ip": "127.0.0.1", "port": 1111,
                 "target": "/", "realm": "lab"}
    verdict = verifier.verify_basic_auth("127.0.0.1", 1111, False, candidate, _context(budget, ["cred-1"]))
    assert verdict.verdict == "inconclusive" and verdict.attempts == 0
    assert budget.used["basic:127.0.0.1:1111/:admin"] == 7
