"""Hunt pipeline: scope guard, discovery, network and web agents, binary triage, verification, attack path, report.

The pipeline is what ``mitigata hunt`` runs. Older single-purpose entry points
(``run``, ``sweep_lan.py``) keep their own tests and remain usable.
"""

from .orchestrator import HuntOptions, HuntRefused, run_hunt

__all__ = ["HuntOptions", "HuntRefused", "run_hunt"]
