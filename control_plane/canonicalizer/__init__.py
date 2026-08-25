"""Target Canonicalizer + the two independent resolvers (§5).

Authorization Resolver ('is this authorized?') and Metadata Resolver ('what is
this resource?') are deliberately separate modules: merging them is the v0.2
bug that v0.3 fixed.

The re-exports below are resolved lazily, and that is not a style choice. D16
gave the Scope Registry a canonicalization step on its write path, so
``registry.scope_registry`` now imports ``canonicalizer.target`` — while
``canonicalizer.authorization`` has always imported ``registry.scope_registry``
for the ``ScopeObject`` type. Importing the submodules eagerly here turned that
into a genuine cycle: touching ``canonicalizer.target`` ran this file, which
ran ``authorization``, which reached back into a half-initialized
``scope_registry``.

There is no cycle between the modules themselves — ``target`` imports nothing
from either — only between the packages, and only because this file pulled in
more than the importer asked for. Deferring means each name still resolves and
nothing is imported until something wants it.

Nothing in the tree imports these names from here; every caller reaches for the
submodule directly. They are kept because removing a package's public surface
to fix an import order would be fixing the wrong thing.
"""

_EXPORTS = {
    "AuthorizationResolution": "control_plane.canonicalizer.authorization",
    "resolve_authorization": "control_plane.canonicalizer.authorization",
    "MetadataResolution": "control_plane.canonicalizer.metadata",
    "resolve_metadata": "control_plane.canonicalizer.metadata",
    "CanonicalizationError": "control_plane.canonicalizer.target",
    "CanonicalTarget": "control_plane.canonicalizer.target",
    "normalize_target": "control_plane.canonicalizer.target",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    """PEP 562 lazy attribute access. See the module docstring for why."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(module_name), name)
