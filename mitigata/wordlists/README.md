# Vendored wordlists

- `web-content-common.txt`: SecLists `Discovery/Web-Content/common.txt` (4,751 entries), copied unchanged on 2026-11-01 from
  https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt
- `LICENSE-SecLists.txt`: the SecLists license (MIT), copied unchanged.

The web agent uses these names as a vocabulary for content-named probes: a name that appears in a fetched page is
requested once, capped per origin. Fuzzing with the full list stays excluded unless the manifest allows `web.fuzz`.
