package compliance.tls.maximum_chain_depth

import rego.v1

# Skip when certificates are absent.
# Warn if the certificate chain length exceeds 4.
# Deep chains increase handshake latency and verification overhead;
# most well-operated PKIs stay at 3 or fewer (leaf + intermediate + root).

default decision := "skip"
default reason := "insufficient input: no certificates present"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

max_chain_depth := 4

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Guard: at least one certificate must be present.
has_certificates if {
    count(input.certificates) > 0
}

chain_too_deep if {
    count(input.certificates) > max_chain_depth
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "warn" if {
    has_certificates
    chain_too_deep
}

decision := "pass" if {
    has_certificates
    not chain_too_deep
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := sprintf("certificate chain length (%d) is within the recommended maximum of %d", [count(input.certificates), max_chain_depth]) if {
    decision == "pass"
}

reason := sprintf("certificate chain length (%d) exceeds the recommended maximum of %d — verify PKI hierarchy", [count(input.certificates), max_chain_depth]) if {
    decision == "warn"
}
