"""Plain-English fixes for each finding class, shared by the report and the dashboard (requirement B-3).

Each class has one fix (what to change) and one check (how to confirm the change worked). The wording describes the
system in general terms. It never contains a credential, a flag or a recovered value.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Remedy:
    fix: str
    check: str


_GENERIC = Remedy(
    fix="No standard fix is written for this type of finding yet. Review the evidence and agree the change with the "
        "system owner.",
    check="Run the same check again after the change. The verdict should no longer be CONFIRMED.",
)

REMEDIES: dict[str, Remedy] = {
    "trusted_header_bypass": Remedy(
        fix="Decide who is trusted from the real connection address, never from a header the visitor sends. Only your "
            "own proxy should be allowed to set X-Forwarded-For, and the application should ignore that header from "
            "every other address.",
        check="Send the same request twice, once without the header and once with a made-up forwarded address. Both "
              "should get the same answer, and the protected page should be refused in both cases.",
    ),
    "passkey_protocol_auth": Remedy(
        fix="Treat the passkey as already known to attackers and replace it. Do not ship the passkey inside the program. "
            "Load it at run time from protected storage, limit guesses per source address, and lock a source out after "
            "a few failures.",
        check="After the change the old passkey should be refused, the new one should work, and repeated wrong guesses "
              "should trigger the lockout.",
    ),
    "information_disclosure_banner": Remedy(
        fix="Make the banner shown before login generic. It should not name the authentication protocol or say where "
            "the secret is kept.",
        check="Connect twice and read the banner each time. It should say nothing about the protocol or the secret.",
    ),
    "hardcoded_secret": Remedy(
        fix="Remove the value from the program and treat it as exposed: replace it, and read the new value at run time "
            "from protected storage. If the program checks a value on its own, move that check to the server.",
        check="Analyse the new build again. The old value should no longer appear in it, and the new value should only "
              "work through the server.",
    ),
    "default_credentials": Remedy(
        fix="Remove the default accounts, give each login its own strong password, lock accounts out after repeated "
            "failures, and require a second factor for administrator logins.",
        check="Try the default logins again. They should be refused, and repeated wrong passwords should trigger the "
              "lockout.",
    ),
    "exposed_path": Remedy(
        fix="Require a real login for the path, move backups, debug files and binaries out of anything publicly served, "
            "and turn off directory listings.",
        check="Request the path without logging in. It should be refused, and the folder should not list its files.",
    ),
    "raw_html_reflection": Remedy(
        fix="Encode any input before it is sent back in a page, and add a Content-Security-Policy header that blocks "
            "inline scripts.",
        check="Send a harmless marker string as the input. It should come back encoded, not as raw HTML.",
    ),
    "static_unsafe_function": Remedy(
        fix="Replace the unbounded copy and command functions (for example gets, strcpy, sprintf and system) with bounded "
            "versions, and check the input lengths that reach them.",
        check="Build the program again and run the binary analysis. The unsafe calls should be gone, or shown to be "
              "unreachable with bounded input.",
    ),
}


def remedy_for(finding_class: str) -> Remedy:
    """The fix and the check for a finding class; a generic pair when the class has no written fix yet."""
    return REMEDIES.get(finding_class, _GENERIC)
