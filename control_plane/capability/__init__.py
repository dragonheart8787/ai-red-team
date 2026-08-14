"""Capability Broker: issuance plus lease/heartbeat renewal, where every renewal
re-runs the full authorization check rather than extending a TTL (§4.6, I9)."""
