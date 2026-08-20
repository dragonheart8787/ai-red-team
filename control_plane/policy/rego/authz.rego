# Authorization policy (ARCHITECTURE.md §5).
#
# Reasons are collected into partial sets and the decision follows a fixed
# precedence: DENY > HUMAN_APPROVAL > ALLOW. The v0.2 draft wrote these as
# complete rules (`decision = "ALLOW" { ... }` beside `decision =
# "HUMAN_APPROVAL" { ... }`), which is not merely untidy: when one input
# satisfies both bodies, OPA raises an evaluation conflict rather than picking
# the first. Correctness cannot rest on conditions being mutually exclusive by
# inspection. Partial set rules are allowed to hold simultaneously, so adding a
# rule can never produce a conflict.
#
# What this policy is allowed to trust is the other half of the design. It
# reads canonical facts from the Authorization Resolver and the Authoritative
# Metadata Registry. It never reads an AI's claim as though it were a fact:
# LLM-derived attributes appear only where they can tighten the outcome (I6b).
package cyberorch.authz

import rego.v1

# ---------------------------------------------------------------------------
# Action pattern matching (§4.1.5)
# ---------------------------------------------------------------------------
# Scope objects carry patterns like "web.*", so exact set membership is not
# enough. A "*" suffix matches at a namespace boundary and nothing else --
# "web.*" covers "web.get" but not "webhook.send". No other wildcard syntax is
# honoured: a scope pattern that quietly matches more than it appears to is a
# way to widen authorization by accident.

pattern_matches(pattern, action) if pattern == action

pattern_matches(pattern, _) if pattern == "*"

pattern_matches(pattern, action) if {
	endswith(pattern, ".*")
	startswith(action, trim_suffix(pattern, "*"))
}

action_allowed(action, allowed) if {
	some pattern in allowed
	pattern_matches(pattern, action)
}

# ---------------------------------------------------------------------------
# Authorization (I8)
# ---------------------------------------------------------------------------
# Derived here from the scope objects themselves rather than taken from the
# resolver's boolean. The control plane computes the same thing independently;
# a bug in one does not silently authorize anything, because both must agree.
#
# Note what is absent: input.action.discovery plays no part. Discovery explains
# how a candidate target was found and may at most trigger escalation below. It
# can never produce authorization.

target_authorized if {
	some scope_object in input.policy.scope_objects
	scope_object.id == input.action.authorization.scope_object_id
	action_allowed(input.action.action, scope_object.allowed_actions)
	scope_covers_target(scope_object)
}

# The Authorization Resolver has already checked type-aware containment (an
# fqdn scope never covers an IP target, a cidr scope never covers an fqdn
# target). Rego re-checks the parts it can see: identity type and value.
scope_covers_target(scope_object) if {
	input.canonical.target.logical_identity.type == "fqdn"
	scope_object.type == "fqdn"
	fqdn_covered(scope_object.value, input.canonical.target.logical_identity.value)
}

scope_covers_target(scope_object) if {
	input.canonical.target.logical_identity.type in {"ip", "cidr"}
	scope_object.type in {"cidr", "ip"}

	# Containment for addresses is computed by the resolver, which has a real
	# IP library. Rego confirms the resolver matched this same scope object
	# rather than re-implementing subnet arithmetic in a policy language.
	input.authorization_resolution.scope_object_id == scope_object.id
	input.authorization_resolution.authorized == true
}

scope_covers_target(scope_object) if {
	input.canonical.target.logical_identity.type in {"url", "repo", "ad_domain"}
	scope_object.type == input.canonical.target.logical_identity.type
	scope_object.value == input.canonical.target.logical_identity.value
}

fqdn_covered(pattern, host) if pattern == host

fqdn_covered(pattern, host) if {
	startswith(pattern, "*.")
	suffix := trim_prefix(pattern, "*")
	endswith(host, suffix)
	host != trim_prefix(suffix, ".")
}

# ---------------------------------------------------------------------------
# Data classification
# ---------------------------------------------------------------------------
# Canonical classes come only from an AUTHORITATIVE registry row; the Metadata
# Resolver leaves them empty otherwise. Observations are the lower tiers
# (OBSERVED / INFERRED / LLM_HINT), kept separate.

canonical_data_class contains class if {
	some class in input.resource_metadata.data_class
}

# Any tier may raise a deny. The asymmetry is deliberate and is what I6b and
# I6c come to: tightening is always permitted, from any source, so an LLM_HINT
# of "PII" still denies -- but only an AUTHORITATIVE row can *clear* a
# prerequisite. An AI can make the system more careful; it cannot make it less.
observed_data_class contains class if {
	some observation in input.resource_metadata.observations
	some class in observation.data_class
}

# ---------------------------------------------------------------------------
# Per-action-class prerequisites (§5, I10)
# ---------------------------------------------------------------------------
# "Unknown is high risk" would be too blunt -- it would stop the passive recon
# whose entire job is to produce classifications. The rule is narrower:
# unknown can never satisfy a prerequisite, and prerequisites are defined per
# action class. Actions that touch content need a known data_class before they
# run. Actions that exist to discover classification do not.

requires_known_classification if {
	some pattern in {"data.*", "web.post", "web.put", "web.delete"}
	pattern_matches(pattern, input.action.action)
}

requires_known_classification if input.action.writes_data == true

requires_known_classification if input.action.changes_state == true

# ---------------------------------------------------------------------------
# deny_reasons (§5)
# ---------------------------------------------------------------------------

deny_reasons contains "target_out_of_scope" if not target_authorized

deny_reasons contains "forbidden_data" if {
	some class in canonical_data_class
	class in {c | some c in input.policy.data_deny}
}

deny_reasons contains "forbidden_data_observed" if {
	some class in observed_data_class
	class in {c | some c in input.policy.data_deny}
}

deny_reasons contains "target_in_deny_scope" if {
	some denied in input.policy.scope_deny
	pattern_matches(denied, input.canonical.target.logical_identity.value)
}

deny_reasons contains "action_denied_by_policy" if {
	input.policy.actions[input.action.action] == "DENY"
}

# An action no layer mentioned is denied (§4.5 merge, all-INHERIT -> DENY).
# merge.py resolves this before the policy is serialized; the check is repeated
# because a missing key must never read as permission.
deny_reasons contains "action_not_in_policy" if {
	not input.policy.actions[input.action.action]
}

deny_reasons contains "over_rate_limit" if not within_rate_limit

# I10: an authorization-critical attribute that is UNKNOWN is handled per
# action class below, but CONFLICT is never survivable. Two authoritative
# classifications disagreeing is the case where guessing is least defensible.
deny_reasons contains "classification_conflict" if {
	input.resource_metadata.classification.authority == "CONFLICT"
}

within_rate_limit if input.policy.rate_limit == null

within_rate_limit if {
	input.policy.rate_limit != null
	input.usage.requests_in_window < input.policy.rate_limit
}

# ---------------------------------------------------------------------------
# approval_reasons (§5, §8.9)
# ---------------------------------------------------------------------------

# I8: a target lifted out of page content is attacker-influenced by
# construction. It escalates regardless of what risk the reviewer assigned.
approval_reasons contains "untrusted_discovery_source" if {
	input.action.discovery.source == "web_content"
}

approval_reasons contains "high_risk" if input.canonical.risk == "high"

# I10: the prerequisite is missing, so the action cannot proceed unattended.
approval_reasons contains "unknown_classification_for_action_class" if {
	requires_known_classification
	input.resource_metadata.known == false
}

# §4.1: possible_sensitive_data_hint is an AI's guess. It may add caution and
# nothing else -- it is never evidence that something is *not* sensitive.
approval_reasons contains "sensitive_data_hint" if {
	count(input.action.possible_sensitive_data_hint) > 0
}

# A lower-tier row flagged data classes the customer never declared. Not a
# deny (the class is not on the deny list) but not nothing either.
approval_reasons contains "non_authoritative_sensitivity" if {
	some class in observed_data_class
	not class in canonical_data_class
}

# ---------------------------------------------------------------------------
# Decision precedence: DENY > HUMAN_APPROVAL > ALLOW
# ---------------------------------------------------------------------------

default decision := "DENY"

decision := "DENY" if count(deny_reasons) > 0

decision := "HUMAN_APPROVAL" if {
	count(deny_reasons) == 0
	count(approval_reasons) > 0
}

decision := "ALLOW" if {
	count(deny_reasons) == 0
	count(approval_reasons) == 0
}

result := {
	"decision": decision,
	"deny_reasons": sort([r | some r in deny_reasons]),
	"approval_reasons": sort([r | some r in approval_reasons]),
}
