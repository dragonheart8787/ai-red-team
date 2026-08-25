# Policy unit tests (§5, §11). Run by `opa test` in CI.
#
# The adversarial fixtures here are permanent regression tests, not a one-off
# demonstration (§10). Their value does not expire when a real model is
# connected -- it increases, because each new model version brings new
# misclassification modes, and what these assert is that the kernel's answer
# does not depend on the model being right.
package cyberorch.authz_test

import data.cyberorch.authz
import rego.v1

# A well-formed, authorized, unremarkable request. Tests override only the
# field under examination, so what each test is actually varying stays visible.
base := {
	"action": {
		"action": "network.scan",
		"authorization": {"source": "engagement_scope", "scope_object_id": "SCOPE-2"},
		"discovery": {"source": "explicit_scope"},
		"possible_sensitive_data_hint": [],
		"writes_data": false,
		"changes_state": false,
	},
	"canonical": {
		"target": {
			"logical_identity": {"type": "ip", "value": "10.20.0.7"},
			"address_count": 1,
		},
		"risk": "low",
	},
	"capability_request": {
		"max_duration_seconds": 120,
		"max_targets": 1,
		"max_concurrency": 1,
		"tool": {},
	},
	"authorization_resolution": {"authorized": true, "scope_object_id": "SCOPE-2"},
	"resource_metadata": {
		"known": true,
		"data_class": ["network_service"],
		"resource_class": ["host"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	},
	"policy": {
		"scope_objects": [{
			"id": "SCOPE-2",
			"type": "cidr",
			"value": "10.20.0.0/24",
			"allowed_actions": ["network.recon", "network.scan"],
		}],
		"scope_allow": "UNIVERSE",
		"scope_deny": [],
		"data_deny": ["PII", "customer_database"],
		"rate_limit": null,
		"actions": {"network.scan": "ALLOW"},
	},
	"usage": {"requests_in_window": 0},
}

# A request for data.read against a web app, authorized by its own scope
# object. Used by the misclassification tests, where the point is that the
# request is otherwise entirely in order.
data_read_base := object.union(base, {
	"action": {
		"action": "data.read",
		"authorization": {"source": "engagement_scope", "scope_object_id": "SCOPE-1"},
	},
	"canonical": {"target": {"logical_identity": {"type": "fqdn", "value": "app.customer-a.com"}}},
	"authorization_resolution": {"authorized": true, "scope_object_id": "SCOPE-1"},
	"policy": {
		"scope_objects": [{
			"id": "SCOPE-1",
			"type": "fqdn",
			"value": "app.customer-a.com",
			"allowed_actions": ["web.*", "data.read"],
		}],
		"actions": {"data.read": "ALLOW"},
	},
})

# ---------------------------------------------------------------------------
# I6b — Attribute Non-Escalation. The reason this stage exists (§10).
# ---------------------------------------------------------------------------

# The Adversarial Fake Reviewer's whole output, in one input: risk "low", no
# sensitive-data hint, and an LLM_HINT row claiming the resource is a static
# site holding nothing. The customer has declared PII at AUTHORITATIVE.
#
# The request is authorized, in scope, under its rate limit, and the action is
# ALLOWed by policy. Every route to DENY is closed except the one that matters,
# so this test cannot pass for an incidental reason.
test_ai_cannot_override_deny_via_misclassification if {
	r := authz.result with input as object.union(data_read_base, {
		"canonical": {"risk": "low"},
		"resource_metadata": {
			"known": true,
			"data_class": ["PII"],
			"classification": {"authority": "AUTHORITATIVE"},
			"observations": [{
				"authority": "LLM_HINT",
				"source": "adversarial_fake_reviewer",
				"data_class": [],
				"resource_class": ["static_site"],
			}],
		},
	})

	r.decision == "DENY"

	# Denied *because of the classification*, not because something else was
	# malformed. The §5 draft of this test omitted the authorization block
	# entirely, so it passed on target_out_of_scope and proved nothing about
	# I6b at all.
	"forbidden_data" in r.deny_reasons
	not "target_out_of_scope" in r.deny_reasons
	not "action_not_in_policy" in r.deny_reasons
}

# Positive control for the test above. Identical input, except the customer
# declared the resource public. It must NOT deny -- otherwise the previous test
# would pass even if the policy denied everything.
test_control_same_request_allowed_when_authoritative_class_is_public if {
	r := authz.result with input as object.union(data_read_base, {
		"canonical": {"risk": "low"},
		"resource_metadata": {
			"known": true,
			"data_class": ["public_marketing"],
			"classification": {"authority": "AUTHORITATIVE"},
			"observations": [],
		},
	})

	r.decision == "ALLOW"
	count(r.deny_reasons) == 0
}

# I6c: a lower tier may tighten. An LLM_HINT of PII denies, even though no
# AUTHORITATIVE row says so -- caution from any source is always accepted.
test_low_tier_hint_can_tighten_into_deny if {
	r := authz.result with input as object.union(data_read_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [{"authority": "LLM_HINT", "data_class": ["PII"]}],
	}})

	r.decision == "DENY"
	"forbidden_data_observed" in r.deny_reasons
}

# The converse, and the sharper half of I6b: a lower tier may not clear a
# prerequisite. data.read needs a known classification; only OBSERVED rows
# exist, so the answer is escalation, never ALLOW.
test_low_tier_cannot_satisfy_a_prerequisite if {
	r := authz.result with input as object.union(data_read_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [{"authority": "OBSERVED", "data_class": ["public_marketing"]}],
	}})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

# ---------------------------------------------------------------------------
# I8 — Authorization Provenance
# ---------------------------------------------------------------------------

test_unknown_scope_object_is_denied if {
	r := authz.result with input as object.union(base, {"action": {"authorization": {
		"source": "engagement_scope",
		"scope_object_id": "SCOPE-DOES-NOT-EXIST",
	}}})

	r.decision == "DENY"
	"target_out_of_scope" in r.deny_reasons
}

test_action_outside_scope_object_allowed_actions_is_denied if {
	r := authz.result with input as object.union(base, {
		"action": {"action": "data.read"},
		"policy": {"actions": {"data.read": "ALLOW"}},
	})

	r.decision == "DENY"
	"target_out_of_scope" in r.deny_reasons
}

# §8.9 (D20): a target introduced only by attacker-controlled observation
# content is attacker-influenced by construction, so it escalates no matter how
# benign the reviewer called it. Keyed on the deterministic fact, not a channel.
test_observation_introduced_target_forces_approval if {
	r := authz.result with input as object.union(base, {
		"action": {"discovery": {"introduced_by_untrusted": true}},
		"canonical": {"risk": "low"},
	})

	r.decision == "HUMAN_APPROVAL"
	"untrusted_discovery_source" in r.approval_reasons
}

# The channel no longer decides: a web_content observation whose target the
# pipeline judged *established* (introduced_by_untrusted false) does not
# escalate. This is the D13 over-escalation the deterministic fact removes.
test_web_channel_alone_does_not_escalate if {
	r := authz.result with input as object.union(base, {
		"action": {"discovery": {"source": "web_content", "introduced_by_untrusted": false}},
		"canonical": {"risk": "low"},
	})

	r.decision == "ALLOW"
	not "untrusted_discovery_source" in r.approval_reasons
}

# The banner gap closes: a target introduced through a tool_output channel — the
# D13/D15 lure lived in an nmap banner — escalates just as a web one does, once
# the fact rather than the channel is what is read.
test_tool_output_introduced_target_also_escalates if {
	r := authz.result with input as object.union(base, {
		"action": {"discovery": {"source": "tool_observed", "introduced_by_untrusted": true}},
		"canonical": {"risk": "low"},
	})

	r.decision == "HUMAN_APPROVAL"
	"untrusted_discovery_source" in r.approval_reasons
}

# ---------------------------------------------------------------------------
# Precedence: DENY > HUMAN_APPROVAL > ALLOW
# ---------------------------------------------------------------------------

# The case that made the v0.2 complete-rule formulation an evaluation conflict:
# deny conditions and approval conditions both hold at once. It must resolve,
# and it must resolve to DENY.
test_deny_beats_approval_when_both_apply if {
	r := authz.result with input as object.union(data_read_base, {
		"action": {"discovery": {"introduced_by_untrusted": true}},
		"canonical": {"risk": "high"},
		"resource_metadata": {
			"known": true,
			"data_class": ["PII"],
			"classification": {"authority": "AUTHORITATIVE"},
			"observations": [],
		},
	})

	r.decision == "DENY"
	count(r.deny_reasons) > 0
	count(r.approval_reasons) > 0
}

test_high_risk_alone_requires_approval if {
	r := authz.result with input as object.union(base, {"canonical": {"risk": "high"}})

	r.decision == "HUMAN_APPROVAL"
	"high_risk" in r.approval_reasons
}

test_clean_request_is_allowed if {
	r := authz.result with input as base

	r.decision == "ALLOW"
	count(r.deny_reasons) == 0
	count(r.approval_reasons) == 0
}

# ---------------------------------------------------------------------------
# I10 — Fail-Closed Ambiguity
# ---------------------------------------------------------------------------

# §5: unknown must not become a blanket "high risk", or passive recon -- whose
# job is to produce classifications in the first place -- could never run.
# network.scan does not list a known classification as a prerequisite.
test_unknown_classification_does_not_block_recon if {
	r := authz.result with input as object.union(base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "ALLOW"
}

test_unknown_classification_blocks_actions_that_write if {
	r := authz.result with input as object.union(base, {
		"action": {"writes_data": true},
		"resource_metadata": {
			"known": false,
			"data_class": [],
			"classification": {"authority": "UNKNOWN"},
			"observations": [],
		},
	})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

# Two authoritative rows disagreeing is never survivable, whatever the action.
test_classification_conflict_always_denies if {
	r := authz.result with input as object.union(base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "CONFLICT"},
		"observations": [],
	}})

	r.decision == "DENY"
	"classification_conflict" in r.deny_reasons
}

# ---------------------------------------------------------------------------
# Rate limit and deny scope
# ---------------------------------------------------------------------------

test_over_rate_limit_denies if {
	r := authz.result with input as object.union(base, {
		"policy": {"rate_limit": 5},
		"usage": {"requests_in_window": 5},
	})

	r.decision == "DENY"
	"over_rate_limit" in r.deny_reasons
}

test_under_rate_limit_allows if {
	r := authz.result with input as object.union(base, {
		"policy": {"rate_limit": 5},
		"usage": {"requests_in_window": 4},
	})

	r.decision == "ALLOW"
}

test_deny_scope_match_denies if {
	r := authz.result with input as object.union(base, {"policy": {"scope_deny": ["10.20.0.7"]}})

	r.decision == "DENY"
	"target_in_deny_scope" in r.deny_reasons
}

# §4.1: the hint may add caution and nothing else.
test_sensitive_data_hint_escalates_but_does_not_deny if {
	r := authz.result with input as object.union(base, {"action": {"possible_sensitive_data_hint": ["pii"]}})

	r.decision == "HUMAN_APPROVAL"
	"sensitive_data_hint" in r.approval_reasons
}

# ---------------------------------------------------------------------------
# Capability budget (§4.6, I3) — D11-4
# ---------------------------------------------------------------------------
# The live run's counterexample, as a permanent regression test: a capability
# request stating max_targets 1 against a /24, which is 256 addresses. Every
# other route to DENY is closed in `base`, so this cannot pass incidentally.

test_target_count_over_budget_denies if {
	r := authz.result with input as object.union(base, {"canonical": {"target": {
		"logical_identity": {"type": "cidr", "value": "10.20.0.0/24"},
		"address_count": 256,
	}}})

	r.decision == "DENY"
	"target_count_exceeds_budget" in r.deny_reasons
}

# The control. Raising the budget to cover the range is the only thing that
# changes, and it is enough -- so the DENY above is about the budget and not
# about the target being a cidr.
test_the_same_range_within_budget_is_allowed if {
	r := authz.result with input as object.union(base, {
		"canonical": {"target": {
			"logical_identity": {"type": "cidr", "value": "10.20.0.0/24"},
			"address_count": 256,
		}},
		"capability_request": {"max_targets": 256},
	})

	r.decision == "ALLOW"
	count(r.deny_reasons) == 0
}

test_exactly_at_the_budget_is_allowed if {
	r := authz.result with input as object.union(base, {
		"canonical": {"target": {
			"logical_identity": {"type": "cidr", "value": "10.20.0.0/30"},
			"address_count": 4,
		}},
		"capability_request": {"max_targets": 4},
	})

	r.decision == "ALLOW"
}

# I10, both directions. A missing budget is not an unlimited one, and a target
# whose size nobody stated is not a target of size one.
test_absent_budget_denies if {
	stripped := json.remove(base, ["capability_request"])
	r := authz.result with input as stripped

	r.decision == "DENY"
	"capability_budget_missing" in r.deny_reasons
}

test_absent_target_count_denies if {
	stripped := json.remove(base, ["canonical/target/address_count"])
	r := authz.result with input as stripped

	r.decision == "DENY"
	"target_count_unknown" in r.deny_reasons
}

test_non_numeric_budget_denies if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_targets": "unlimited"}})

	r.decision == "DENY"
	"capability_budget_missing" in r.deny_reasons
}

# ---------------------------------------------------------------------------
# Action pattern matching (§4.1.5)
# ---------------------------------------------------------------------------

test_namespace_wildcard_matches_within_namespace if {
	authz.action_allowed("web.get", ["web.*"])
	authz.action_allowed("web.post.form", ["web.*"])
	authz.action_allowed("network.scan", ["network.recon", "network.scan"])
	authz.action_allowed("anything.at.all", ["*"])
}

test_namespace_wildcard_does_not_leak_across_names if {
	not authz.action_allowed("webhook.send", ["web.*"])
	not authz.action_allowed("web", ["web.*"])
	not authz.action_allowed("network.scan", ["network.recon"])
	not authz.action_allowed("data.read", [])
}

test_wildcard_fqdn_scope_covers_subdomains_only if {
	authz.fqdn_covered("*.customer-a.com", "app.customer-a.com")
	not authz.fqdn_covered("*.customer-a.com", "customer-a.com")
	not authz.fqdn_covered("*.customer-a.com", "evil-customer-a.com")
}
