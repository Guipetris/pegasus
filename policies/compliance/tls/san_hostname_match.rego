package compliance.tls.san_hostname_match

import rego.v1

# Verifies that the probed hostname appears in the Subject Alternative Names of
# the leaf certificate (first in the chain).
#
# Per RFC 6125 §6.4, clients MUST use SANs for hostname verification; the CN is
# deprecated for this purpose (CA/BF Baseline Requirements v2 §7.1.4).
#
# Wildcard matching: a SAN of "*.example.com" matches "api.example.com" but NOT
# "example.com" or "sub.api.example.com".
#
# Decision set:
#   skip — no certificates present, no SANs on the leaf cert, or no target host available
#   pass — target hostname matches at least one SAN
#   warn — target hostname NOT found in SANs (potential misconfiguration)

default decision := "skip"
default reason := "insufficient input: no certificates or no SANs on leaf certificate"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

leaf_cert := input.certificates[0]

has_leaf_cert if {
    count(input.certificates) > 0
}

has_sans if {
    has_leaf_cert
    count(leaf_cert.subject_alt_names) > 0
}

has_target_host if {
    input.target.host != null
    input.target.host != ""
}

# Strip leading "*." from a wildcard SAN to get the domain suffix.
wildcard_suffix(san) := suffix if {
    startswith(san, "*.")
    suffix := substring(san, 2, -1)
}

# A hostname matches a SAN if they are equal (case-insensitive via lower()).
san_exact_match(host, san) if {
    lower(host) == lower(san)
}

# A hostname matches a wildcard SAN "*.suffix" if:
# - the hostname ends with ".suffix"
# - the hostname has exactly one label to the left of ".suffix" (no nested wildcards)
san_wildcard_match(host, san) if {
    suffix := wildcard_suffix(san)
    lower_host := lower(host)
    lower_suffix := lower(suffix)
    endswith(lower_host, concat("", [".", lower_suffix]))
    # Ensure the part before the suffix is a single label (no dots)
    prefix := substring(lower_host, 0, count(lower_host) - count(lower_suffix) - 1)
    not contains(prefix, ".")
    count(prefix) > 0
}

host_in_sans(host) if {
    some san in leaf_cert.subject_alt_names
    san_exact_match(host, san)
}

host_in_sans(host) if {
    some san in leaf_cert.subject_alt_names
    san_wildcard_match(host, san)
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "pass" if {
    has_sans
    has_target_host
    host_in_sans(input.target.host)
}

decision := "warn" if {
    has_sans
    has_target_host
    not host_in_sans(input.target.host)
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := sprintf("hostname %q found in certificate SANs — RFC 6125 §6.4 satisfied", [input.target.host]) if {
    decision == "pass"
}

reason := sprintf(
    "hostname %q NOT found in certificate SANs %v — potential hostname mismatch (RFC 6125 §6.4, CA/BF BR v2 §7.1.4)",
    [input.target.host, leaf_cert.subject_alt_names],
) if {
    decision == "warn"
}
