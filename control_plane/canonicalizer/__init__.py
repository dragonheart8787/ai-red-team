"""Target Canonicalizer + the two independent resolvers (§5).

Authorization Resolver ('is this authorized?') and Metadata Resolver ('what is
this resource?') are deliberately separate modules: merging them is the v0.2
bug that v0.3 fixed.
"""

from control_plane.canonicalizer.authorization import (
    AuthorizationResolution,
    resolve_authorization,
)
from control_plane.canonicalizer.metadata import MetadataResolution, resolve_metadata
from control_plane.canonicalizer.target import (
    CanonicalizationError,
    CanonicalTarget,
    normalize_target,
)

__all__ = [
    "AuthorizationResolution",
    "CanonicalTarget",
    "CanonicalizationError",
    "MetadataResolution",
    "normalize_target",
    "resolve_authorization",
    "resolve_metadata",
]
