# Constraint algebra boundary cases as the policy reads them (§4.5, §11).
#
# merge.py computes the effective policy and tests/test_merge.py checks that
# computation directly. These tests cover the other half: that the *policy*
# interprets each merged shape the way the algebra intended. A merge that
# correctly produces UNIVERSE is no help if the Rego then treats UNIVERSE as an
# empty allow list, and a null rate_limit meaning "no limit" is worth nothing
# if the policy reads null as zero.
#
# Three cases per constraint, per §4.5: nothing set, one layer set, several
# layers in conflict.
package cyberorch.constraint_algebra_test

import data.cyberorch.authz
import rego.v1

base_request := {
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
	# One address, one target: within budget, so nothing here is about the
	# §4.6 capability budget. These tests are about the constraint algebra and
	# a budget deny would mask what they assert.
	"capability_request": {"max_targets": 1},
	"authorization_resolution": {"authorized": true, "scope_object_id": "SCOPE-2"},
	"resource_metadata": {
		"known": true,
		"data_class": ["network_service"],
		"resource_class": ["host"],
		"classification": {"authority": "AUTHORITATIVE"},
		"observations": [],
	},
	"usage": {"requests_in_window": 3},
}

scope_objects := [{
	"id": "SCOPE-2",
	"type": "cidr",
	"value": "10.20.0.0/24",
	"allowed_actions": ["network.recon", "network.scan"],
}]

# Build a request carrying a given merged policy.
request(policy) := object.union(base_request, {"policy": object.union(
	{"scope_objects": scope_objects},
	policy,
)})

# ---------------------------------------------------------------------------
# Nothing set in any layer
# ---------------------------------------------------------------------------

# merge_policy over four neutral layers, serialized. The action map is empty
# because no layer mentioned anything.
all_unset_policy := {
	"scope_allow": "UNIVERSE",
	"scope_deny": [],
	"data_deny": [],
	"rate_limit": null,
	"actions": {},
}

# All-INHERIT resolves to DENY. Silence is not permission (I10).
test_all_layers_unset_denies_the_action if {
	r := authz.result with input as request(all_unset_policy)

	r.decision == "DENY"
	"action_not_in_policy" in r.deny_reasons
}

# ...but it must deny for that reason alone. UNIVERSE must not be read as an
# empty allow list, and a null rate_limit must not be read as a limit of zero.
test_all_layers_unset_does_not_deny_for_scope_or_rate_limit if {
	r := authz.result with input as request(all_unset_policy)

	not "target_out_of_scope" in r.deny_reasons
	not "over_rate_limit" in r.deny_reasons
	not "target_in_deny_scope" in r.deny_reasons
	not "forbidden_data" in r.deny_reasons
}

# ---------------------------------------------------------------------------
# One layer set
# ---------------------------------------------------------------------------

# The regression §4.5 is built around: an Emergency Overlay is live, and it
# sets only a data_deny. Everything it stays silent about must be untouched.
test_overlay_tightening_one_field_leaves_the_rest_alone if {
	r := authz.result with input as request({
		"scope_allow": "UNIVERSE",
		"scope_deny": [],
		"data_deny": ["secrets"],
		"rate_limit": null,
		"actions": {"network.scan": "ALLOW"},
	})

	r.decision == "ALLOW"
}

test_single_layer_rate_limit_is_enforced if {
	r := authz.result with input as request({
		"scope_allow": "UNIVERSE",
		"scope_deny": [],
		"data_deny": [],
		"rate_limit": 3,
		"actions": {"network.scan": "ALLOW"},
	})

	r.decision == "DENY"
	"over_rate_limit" in r.deny_reasons
}

test_single_layer_data_deny_is_enforced if {
	r := authz.result with input as request({
		"scope_allow": "UNIVERSE",
		"scope_deny": [],
		"data_deny": ["network_service"],
		"rate_limit": null,
		"actions": {"network.scan": "ALLOW"},
	})

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
}

# ---------------------------------------------------------------------------
# Several layers in conflict
# ---------------------------------------------------------------------------

# baseline ALLOW, overlay DENY. merge_policy resolves that to DENY before OPA
# sees it; this confirms the policy acts on the merged verdict rather than
# reaching its own conclusion about which layer should win.
test_merged_deny_is_honoured if {
	r := authz.result with input as request({
		"scope_allow": "UNIVERSE",
		"scope_deny": [],
		"data_deny": [],
		"rate_limit": null,
		"actions": {"network.scan": "DENY"},
	})

	r.decision == "DENY"
	"action_denied_by_policy" in r.deny_reasons
}

# Layers set 100, 20 and 50; the merged value is 20, and 20 is what binds.
test_merged_minimum_rate_limit_binds if {
	over := authz.result with input as object.union(
		request({
			"scope_allow": "UNIVERSE",
			"scope_deny": [],
			"data_deny": [],
			"rate_limit": 20,
			"actions": {"network.scan": "ALLOW"},
		}),
		{"usage": {"requests_in_window": 20}},
	)

	under := authz.result with input as object.union(
		request({
			"scope_allow": "UNIVERSE",
			"scope_deny": [],
			"data_deny": [],
			"rate_limit": 20,
			"actions": {"network.scan": "ALLOW"},
		}),
		{"usage": {"requests_in_window": 19}},
	)

	over.decision == "DENY"
	"over_rate_limit" in over.deny_reasons
	under.decision == "ALLOW"
}

# Unioned deny lists from several layers all bind, not just the last one.
test_merged_union_of_deny_lists_all_bind if {
	r := authz.result with input as object.union(
		request({
			"scope_allow": "UNIVERSE",
			"scope_deny": [],
			"data_deny": ["PII", "customer_database", "network_service"],
			"rate_limit": null,
			"actions": {"network.scan": "ALLOW"},
		}),
		{"resource_metadata": {"data_class": ["customer_database"]}},
	)

	r.decision == "DENY"
	"forbidden_data" in r.deny_reasons
}
