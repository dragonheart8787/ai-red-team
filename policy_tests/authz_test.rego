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

# §5 row 2, applied to a read (D32). web.get returns the resource's whole
# document -- the thing data_class describes -- so it lists a known
# classification as a prerequisite, unlike the banner-fragment recon above.
web_get_base := object.union(base, {
	"action": {"action": "web.get"},
	"policy": {
		"actions": {"web.get": "ALLOW"},
		"scope_objects": [{
			"id": "SCOPE-2",
			"type": "cidr",
			"value": "10.20.0.0/24",
			"allowed_actions": ["network.recon", "network.scan", "web.get"],
		}],
	},
})

test_web_get_without_a_classification_needs_a_human if {
	r := authz.result with input as object.union(web_get_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

# The measured cost of the rule above, pinned. web.get targets are ip/fqdn, and
# those are the types the registry classifies in practice -- the D11 live target
# carries AUTHORITATIVE network_service -- so the ordinary case still runs
# unattended and the tool is not made unusable by the prerequisite.
test_web_get_against_a_classified_host_still_runs_unattended if {
	r := authz.result with input as web_get_base

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

# Deny still dominates: a denied class is refused outright rather than offered
# to a human, exactly as it is for every other action.
test_web_get_against_denied_data_is_denied_not_escalated if {
	r := authz.result with input as object.union(web_get_base, {"resource_metadata": {
		"known": true,
		"data_class": ["PII"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
}

# The precedence check the new prerequisite could have disturbed: when the
# classification is unknown *and* an observation names a denied class, both a
# deny reason and an approval reason are collected, and DENY must win.
#
# Mutation testing found this is guarded twice, which is worth recording so the
# result is not misread. Weakening only the explicit rule -- adding
# `count(approval_reasons) == 0` to the DENY branch -- leaves this test green,
# because no branch then matches and `default decision := "DENY"` catches it.
# Flipping the explicit rule *and* the default together turns it red. So the
# test does hold the property; the surviving single mutant is the fail-closed
# default doing its job, not a gap.
test_web_get_deny_dominates_when_both_reasons_are_present if {
	r := authz.result with input as object.union(web_get_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [{"authority": "OBSERVED", "source": "banner", "data_class": ["PII"]}],
	}})

	r.decision == "DENY"
	"forbidden_data_observed" in r.deny_reasons
	"unknown_classification_for_action_class" in r.approval_reasons
}

# Adding web.get must not widen the namespace: a scan of an unclassified host
# is still unattended recon, which is the distinction §5's table draws.
test_adding_web_get_did_not_make_recon_require_a_classification if {
	r := authz.result with input as object.union(base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "ALLOW"
}

# code.* joined at D43 (ADR_SEMGREP.md §2.1), argued independently of D32's
# web.get reasoning rather than inherited from it: running a source-code
# scanner necessarily ingests the whole repository, and a finding's evidence
# is a verbatim quote of it. The three cases mirror D32's own three exactly.
code_scan_base := object.union(base, {
	"action": {"action": "code.scan"},
	"canonical": {
		"target": {
			"logical_identity": {"type": "repo", "value": "github.com/acme/backend:main"},
			"address_count": 1,
		},
		"risk": "low",
	},
	"policy": {
		"actions": {"code.scan": "ALLOW"},
		"scope_objects": [{
			"id": "SCOPE-2",
			"type": "repo",
			"value": "github.com/acme/backend:main",
			"allowed_actions": ["code.scan"],
		}],
	},
})

test_code_scan_against_an_unclassified_repo_needs_a_human if {
	r := authz.result with input as object.union(code_scan_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

test_code_scan_against_a_classified_non_sensitive_repo_runs_unattended if {
	r := authz.result with input as object.union(code_scan_base, {"resource_metadata": {
		"known": true,
		"data_class": ["source_code"],
		"resource_class": ["repository"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

test_code_scan_against_a_deny_listed_repo_is_denied_not_escalated if {
	r := authz.result with input as object.union(code_scan_base, {"resource_metadata": {
		"known": true,
		"data_class": ["PII"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
}

# code.secrets (D55, docs/ADR_GITLEAKS.md D55-2). D43-3 is carried, not
# inherited: the `code.*` pattern already matches it, and these three cases
# are what stop that from being an accident of a wildcard. The argument for it
# is stronger than for code.scan -- this action's whole output is an inventory of
# where the customer's credentials are -- and the last case is the reason a
# repository nobody has classified must not be scanned unattended.
code_secrets_base := object.union(code_scan_base, {
	"action": {"action": "code.secrets"},
	"policy": {
		"actions": {"code.secrets": "ALLOW"},
		"scope_objects": [{
			"id": "SCOPE-2",
			"type": "repo",
			"value": "github.com/acme/backend:main",
			"allowed_actions": ["code.secrets"],
		}],
	},
})

test_code_secrets_against_an_unclassified_repo_needs_a_human if {
	r := authz.result with input as object.union(code_secrets_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

test_code_secrets_against_a_classified_non_sensitive_repo_runs_unattended if {
	r := authz.result with input as object.union(code_secrets_base, {"resource_metadata": {
		"known": true,
		"data_class": ["source_code"],
		"resource_class": ["repository"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

test_code_secrets_against_a_deny_listed_repo_is_denied_not_escalated if {
	r := authz.result with input as object.union(code_secrets_base, {"resource_metadata": {
		"known": true,
		"data_class": ["PII"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
}

# A scope for code.scan does not authorize code.secrets: allowed_actions is per
# action, and reading a repository's history for credentials is not a
# consequence of being allowed to run a static analyzer over its tree.
test_a_code_scan_scope_does_not_authorize_code_secrets if {
	r := authz.result with input as object.union(code_secrets_base, {
		"policy": {
			"actions": {"code.secrets": "ALLOW"},
			"scope_objects": [{
				"id": "SCOPE-2",
				"type": "repo",
				"value": "github.com/acme/backend:main",
				"allowed_actions": ["code.scan"],
			}],
		},
		"resource_metadata": {
			"known": true,
			"data_class": ["source_code"],
			"classification": {"authority": "AUTHORITATIVE"},
			"observations": [],
		},
	})

	r.decision == "DENY"
	"target_out_of_scope" in r.deny_reasons
}

# web.render joined at ACCEPTANCE 5.48, on D32's argument unchanged (a rendered page
# is the whole document a GET returns, after the target's JavaScript has run). The
# three cases are D32's own three, for the action D36 added after it.
web_render_base := object.union(base, {
	"action": {"action": "web.render"},
	"policy": {
		"actions": {"web.render": "ALLOW"},
		"scope_objects": [{
			"id": "SCOPE-2",
			"type": "cidr",
			"value": "10.20.0.0/24",
			"allowed_actions": ["network.recon", "network.scan", "web.render"],
		}],
	},
})

test_web_render_against_an_unclassified_host_needs_a_human if {
	r := authz.result with input as object.union(web_render_base, {"resource_metadata": {
		"known": false,
		"data_class": [],
		"classification": {"authority": "UNKNOWN"},
		"observations": [],
	}})

	r.decision == "HUMAN_APPROVAL"
	"unknown_classification_for_action_class" in r.approval_reasons
}

test_web_render_against_a_classified_non_sensitive_host_runs_unattended if {
	r := authz.result with input as object.union(web_render_base, {"resource_metadata": {
		"known": true,
		"data_class": ["network_service"],
		"resource_class": ["web_content"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

test_web_render_against_denied_data_is_denied_not_escalated if {
	r := authz.result with input as object.union(web_render_base, {"resource_metadata": {
		"known": true,
		"data_class": ["PII"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	}})

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
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
# Capability duration ceiling (D58-16, D64)
# ---------------------------------------------------------------------------
# `base` states 120 s, so every other test in this file already passes the ceiling. These pin the
# boundary and both fail-closed directions; the number itself is compared with the Python side in
# tests/test_duration_ceiling.py.

test_a_duration_at_the_ceiling_is_allowed if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": 1800}})

	r.decision == "ALLOW"
	count(r.deny_reasons) == 0
}

test_a_duration_one_second_over_the_ceiling_denies if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": 1801}})

	r.decision == "DENY"
	"budget_duration_exceeds_ceiling" in r.deny_reasons
}

test_a_day_long_duration_denies if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": 86400}})

	r.decision == "DENY"
	"budget_duration_exceeds_ceiling" in r.deny_reasons
}

test_a_zero_or_negative_duration_denies if {
	zero := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": 0}})
	negative := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": -5}})

	"budget_duration_invalid" in zero.deny_reasons
	"budget_duration_invalid" in negative.deny_reasons
	zero.decision == "DENY"
	negative.decision == "DENY"
}

# I10: no stated duration is not an unlimited one.
test_an_absent_duration_denies if {
	stripped := json.remove(base, ["capability_request/max_duration_seconds"])
	r := authz.result with input as stripped

	r.decision == "DENY"
	"budget_duration_missing" in r.deny_reasons
}

test_a_non_numeric_duration_denies if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": "600"}})

	r.decision == "DENY"
	"budget_duration_missing" in r.deny_reasons
}

# The ceiling answers the duration and nothing else: a duration over it adds one reason and does
# not disturb the others, and a request that is fine except for its duration has exactly that one.
test_the_duration_ceiling_is_the_only_reason_when_it_is_the_only_problem if {
	r := authz.result with input as object.union(base, {"capability_request": {"max_duration_seconds": 3600}})

	count(r.deny_reasons) == 1
	"budget_duration_exceeds_ceiling" in r.deny_reasons
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

# ---------------------------------------------------------------------------
# D68 P1 -- the relation between a proposal and the task it names
#
# A fact computed by the control plane and stored with the decision, read by approval_reasons alone,
# and only when the policy's task_relation_enforce is on. It can ask for a human; nothing else.
# ---------------------------------------------------------------------------

enforced := object.union(base, {"policy": object.union(base.policy, {"task_relation_enforce": true})})

relation(name) := {"version": "plan_fit_v1", "task_relation": name, "sub_cause": null}

test_matches_task_is_the_same_as_no_signal if {
	with_signal := authz.result with input as object.union(enforced, {"plan_fit": relation("matches_task")})
	without := authz.result with input as enforced

	with_signal == without
	with_signal.decision == "ALLOW"
}

# DP-13: a match by containment is a match; the sub-cause is for counting and the policy does not read it.
test_a_subset_of_the_task_range_is_the_same_as_a_match_when_enforced if {
	signal := {"version": "plan_fit_v1", "task_relation": "matches_task", "sub_cause": "subset_of_task_range"}
	with_signal := authz.result with input as object.union(enforced, {"plan_fit": signal})
	without := authz.result with input as enforced

	with_signal == without
	with_signal.decision == "ALLOW"
}

test_no_task_asks_for_a_human_when_enforced if {
	r := authz.result with input as object.union(enforced, {"plan_fit": relation("no_task")})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["proposal_without_task"]
}

test_a_task_that_differs_or_is_not_live_asks_for_a_human_when_enforced if {
	every name in ["differs_from_task", "task_not_live"] {
		r := authz.result with input as object.union(enforced, {"plan_fit": relation(name)})
		r.decision == "HUMAN_APPROVAL"
		r.approval_reasons == ["proposal_outside_task"]
	}
}

test_nothing_is_read_when_not_enforced if {
	every name in ["no_task", "differs_from_task", "task_not_live", "matches_task", "unrecognized"] {
		r := authz.result with input as object.union(base, {"plan_fit": relation(name)})
		r.decision == "ALLOW"
		count(r.approval_reasons) == 0
	}
}

test_an_explicit_false_switch_reads_nothing if {
	off := object.union(base, {"policy": object.union(base.policy, {"task_relation_enforce": false})})
	r := authz.result with input as object.union(off, {"plan_fit": relation("no_task")})

	r.decision == "ALLOW"
}

test_an_absent_signal_fires_nothing_even_when_enforced if {
	r := authz.result with input as enforced

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

test_a_signal_this_policy_cannot_read_is_outside_the_plan if {
	bad := [
		relation("unrecognized"),
		relation("some_value_from_a_newer_vocabulary"),
		{"version": "plan_fit_v1"},
		{"task_relation": 7},
		"matches_task",
		null,
	]
	every signal in bad {
		r := authz.result with input as object.union(enforced, {"plan_fit": signal})
		r.decision == "HUMAN_APPROVAL"
		"proposal_outside_task" in r.approval_reasons
	}
}

test_the_signal_never_outranks_a_deny if {
	denied := object.union(enforced, {"authorization_resolution": {"authorized": false, "scope_object_id": null}})
	plain := authz.result with input as denied
	with_signal := authz.result with input as object.union(denied, {"plan_fit": relation("no_task")})

	plain.decision == "DENY"
	with_signal.decision == "DENY"
	with_signal.deny_reasons == plain.deny_reasons
}

test_the_signal_adds_to_other_reasons_and_never_replaces_them if {
	worried := object.union(enforced, {"canonical": {"risk": "high"}})
	r := authz.result with input as object.union(worried, {"plan_fit": relation("no_task")})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["high_risk", "proposal_without_task"]
}

# ---------------------------------------------------------------------------
# D68 Q1 -- whether the task's goal, action and target fit each other
#
# A validator's judgement, stored with the decision, read by approval_reasons alone, and only when the
# policy's goal_fit_enforce is on. It can ask for a human; nothing else. `plausible` is read by no rule.
# ---------------------------------------------------------------------------

goal_enforced := object.union(base, {"policy": object.union(base.policy, {"goal_fit_enforce": true})})

fit(value, cause) := {
	"version": "plan_fit_v1",
	"task_relation": "matches_task",
	"sub_cause": null,
	"goal_fit": value,
	"goal_fit_cause": cause,
}

test_plausible_is_the_same_as_no_signal if {
	with_signal := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("plausible", null)})
	without := authz.result with input as goal_enforced

	with_signal == without
	with_signal.decision == "ALLOW"
}

test_implausible_asks_for_a_human_when_enforced if {
	r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("implausible", null)})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["plan_implausible"]
}

test_cannot_tell_asks_for_a_human_under_its_own_name if {
	r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("insufficient_context", null)})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["plan_unverified"]
}

test_a_check_that_failed_asks_for_a_human if {
	r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("not_assessed", "failed")})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["plan_check_failed"]
}

test_a_check_that_was_never_asked_adds_nothing if {
	every cause in ["disabled", "not_applicable", "class_not_enabled", "class_suspended"] {
		r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("not_assessed", cause)})
		r.decision == "ALLOW"
		count(r.approval_reasons) == 0
	}
}

# D68 DP-15. A class outside the operator's list is not asked; a class the control plane took out of
# it is not asked either. Neither is a check that failed, so neither may raise `plan_check_failed`.
# With the switch ON the decision for such a class is exactly the decision with the switch OFF.
test_a_class_outside_the_list_with_the_switch_on_decides_as_with_the_switch_off if {
	every cause in ["class_not_enabled", "class_suspended"] {
		signal := {"plan_fit": fit("not_assessed", cause)}
		on := authz.result with input as object.union(goal_enforced, signal)
		off := authz.result with input as object.union(base, signal)

		on == off
		on.decision == "ALLOW"
		not "plan_check_failed" in on.approval_reasons
	}
}

test_a_failed_check_still_asks_when_a_class_is_in_the_list if {
	# the contrast that gives the two tests above their meaning: the cause alone decides
	failed := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("not_assessed", "failed")})
	quiet := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("not_assessed", "class_not_enabled")})

	failed.approval_reasons == ["plan_check_failed"]
	count(quiet.approval_reasons) == 0
}

test_a_cause_the_policy_does_not_know_is_not_quiet if {
	every cause in ["class_unknown", "", null, 7, "Class_Not_Enabled"] {
		r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit("not_assessed", cause)})
		r.approval_reasons == ["plan_check_failed"]
	}
}

test_a_decision_from_before_the_validator_existed_has_no_goal_fit_and_fires_nothing if {
	old := {"version": "plan_fit_v1", "task_relation": "matches_task", "sub_cause": null}
	r := authz.result with input as object.union(goal_enforced, {"plan_fit": old})

	r.decision == "ALLOW"
	count(r.approval_reasons) == 0
}

test_nothing_is_read_when_the_goal_switch_is_off if {
	every value in ["implausible", "insufficient_context", "not_assessed", "unrecognized", "plausible"] {
		r := authz.result with input as object.union(base, {"plan_fit": fit(value, "failed")})
		r.decision == "ALLOW"
		count(r.approval_reasons) == 0
	}
}

test_a_value_this_policy_cannot_read_is_a_check_that_failed if {
	every value in ["unrecognized", "some_value_from_a_newer_vocabulary", null, false, 7, "", ["plausible"], {"a": 1}] {
		r := authz.result with input as object.union(goal_enforced, {"plan_fit": fit(value, null)})
		r.decision == "HUMAN_APPROVAL"
		"plan_check_failed" in r.approval_reasons
	}
}

test_the_two_switches_are_independent if {
	no_task_only := object.union(base, {"plan_fit": {"version": "plan_fit_v1", "task_relation": "no_task", "sub_cause": "task_id_absent", "goal_fit": "implausible", "goal_fit_cause": null}})

	# the goal switch alone: only the goal's reason
	goal_only := authz.result with input as object.union(no_task_only, {"policy": object.union(base.policy, {"goal_fit_enforce": true})})
	goal_only.approval_reasons == ["plan_implausible"]

	# the relation switch alone: only the relation's reason
	task_only := authz.result with input as object.union(no_task_only, {"policy": object.union(base.policy, {"task_relation_enforce": true})})
	task_only.approval_reasons == ["proposal_without_task"]

	# both: both
	both := authz.result with input as object.union(no_task_only, {"policy": object.union(base.policy, {"task_relation_enforce": true, "goal_fit_enforce": true})})
	both.approval_reasons == ["plan_implausible", "proposal_without_task"]
}

test_the_goal_signal_never_outranks_a_deny if {
	denied := object.union(goal_enforced, {"authorization_resolution": {"authorized": false, "scope_object_id": null}})
	plain := authz.result with input as denied
	with_signal := authz.result with input as object.union(denied, {"plan_fit": fit("implausible", null)})

	plain.decision == "DENY"
	with_signal.decision == "DENY"
	with_signal.deny_reasons == plain.deny_reasons
}

test_the_goal_signal_adds_to_other_reasons_and_never_replaces_them if {
	worried := object.union(goal_enforced, {"canonical": {"risk": "high"}})
	r := authz.result with input as object.union(worried, {"plan_fit": fit("implausible", null)})

	r.decision == "HUMAN_APPROVAL"
	r.approval_reasons == ["high_risk", "plan_implausible"]
}
