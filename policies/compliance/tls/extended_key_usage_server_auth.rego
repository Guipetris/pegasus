package compliance.tls.extended_key_usage_server_auth

import rego.v1

# Verifies that the leaf certificate (first in chain) has the id-kp-serverAuth
# Extended Key Usage OID (1.3.6.1.5.5.7.3.1).
#
# CA/Browser Forum Baseline Requirements v2 §7.1.2 requires TLS server certificates
# to include the serverAuth EKU.  RFC 5280 §4.2.1.12 defines the EKU extension.
#
# Decision set:
#   skip — no certificates present, or EKU extension absent on the leaf cert
#          (some legacy certs omit EKU; skipping rather than failing to reduce noise)
#   pass — leaf cert's EKU contains "serverAuth"
#   fail — leaf cert has an EKU extension but "serverAuth" is absent

default decision := "skip"
default reason := "insufficient input: no certificates present or EKU extension absent on leaf certificate"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

leaf_cert := input.certificates[0]

has_leaf_cert if {
    count(input.certificates) > 0
}

leaf_is_not_ca if {
    has_leaf_cert
    leaf_cert.is_ca != true
}

has_eku if {
    has_leaf_cert
    count(leaf_cert.extended_key_usage) > 0
}

has_server_auth if {
    some eku in leaf_cert.extended_key_usage
    eku == "serverAuth"
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "pass" if {
    has_eku
    leaf_is_not_ca
    has_server_auth
}

decision := "fail" if {
    has_eku
    leaf_is_not_ca
    not has_server_auth
}

# CA certificates don't require serverAuth EKU — skip them.
decision := "skip" if {
    has_leaf_cert
    leaf_cert.is_ca == true
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "leaf certificate contains serverAuth EKU — compliant with CA/BF BR v2 §7.1.2" if {
    decision == "pass"
}

reason := sprintf(
    "leaf certificate EKU does not include serverAuth — non-compliant with CA/BF BR v2 §7.1.2; present EKUs: %v",
    [leaf_cert.extended_key_usage],
) if {
    decision == "fail"
}

reason := "leaf certificate is a CA certificate — serverAuth EKU check does not apply" if {
    decision == "skip"
    has_leaf_cert
    leaf_cert.is_ca == true
}
