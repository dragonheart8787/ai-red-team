"""The five switches for irreversible actions: each off, each turned on by a person at a terminal
(completion 3, item 4; ACCEPTANCE 5.92).

An irreversible action is a kill, a removal or an unlink. The plan may *ask* for any of them; what
the act half does about it is decided here, per category:

=============  ======================================================  ==========================
``kill``       ``kill_container``                                      ``--enable kill``
``container``  ``remove_container``                                    ``--enable container``
``proxy``      ``remove_proxy``                                        ``--enable proxy``
``network``    ``remove_network``                                      refused in this version
``file``       ``unlink_file``                                         refused in this version
=============  ======================================================  ==========================

The rules, each pinned by a test:

* **off by default**, every one of them. A category that is not enabled is carried out as
  ``skipped_deletions_off`` and the Docker client is not touched;
* **the command line is the only way on.** No environment variable, configuration key, file or
  default turns one on, and ``Settings`` is built from the operator's words in exactly one place
  (:func:`validate`, through ``act.settings_for``);
* **a person confirms at a terminal.** ``scripts/run_reconciler.py`` shows what the run may do and
  wants the :func:`phrase` typed back, on a stdin and a stdout that are both terminals. There is no
  ``--yes``; a script, a pipe, a cron job or a service manager cannot answer it. (The terminal
  half lives in the command line, not in this package: nothing here reads or writes a stream.)
* **two categories are not available yet** (``network``, ``file``): they are recognised and
  refused at argument validation, before the configuration is read and before anything is opened;
* **what was enabled is on the record**: ``reconciler.started`` carries the sorted list.
"""

from __future__ import annotations

from collections.abc import Iterable

from control_plane.reconciler import vocab

KILL = "kill"
CONTAINER = "container"
PROXY = "proxy"
NETWORK = "network"
FILE = "file"
CATEGORIES = (KILL, CONTAINER, PROXY, NETWORK, FILE)

#: the action kinds each category covers
KINDS: dict[str, tuple[str, ...]] = {
    KILL: (vocab.KILL_CONTAINER,),
    CONTAINER: (vocab.REMOVE_CONTAINER,),
    PROXY: (vocab.REMOVE_PROXY,),
    NETWORK: (vocab.REMOVE_NETWORK,),
    FILE: (vocab.UNLINK_FILE,),
}
CATEGORY_OF = {kind: category for category, kinds in KINDS.items() for kind in kinds}

#: what an operator may turn on in this version
OPERATOR_MAY_ENABLE = (KILL, CONTAINER, PROXY)
#: what the library accepts in a ``Settings`` (the tests of the act half use all five)
EVERYTHING = frozenset(CATEGORIES)

class FlagRefused(ValueError):  # noqa: N818 - a refusal of an operator's words, not a failure
    """The operator's switches are not acceptable; the message says which and why."""


def validate(names: Iterable[str]) -> frozenset[str]:
    """The categories an operator asked for, or :class:`FlagRefused`.

    Only the exact lower-case names are understood: no ``all``, no abbreviation, no comma list, no
    empty word. Naming one twice is the same as naming it once."""
    chosen: set[str] = set()
    for name in names:
        if name not in CATEGORIES:
            raise FlagRefused(f"--enable {name!r}: not a category (the categories are "
                              f"{', '.join(CATEGORIES)}; there is no 'all')")
        if name not in OPERATOR_MAY_ENABLE:
            raise FlagRefused(f"--enable {name}: this category cannot be enabled in this version "
                              f"(only {', '.join(OPERATOR_MAY_ENABLE)} can)")
        chosen.add(name)
    return frozenset(chosen)


def phrase(categories: Iterable[str]) -> str:
    """What the person types: ``enable`` and the categories, sorted, one space apart."""
    return "enable " + " ".join(sorted(categories))
