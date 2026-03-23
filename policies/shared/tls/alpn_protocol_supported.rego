package shared.tls.alpn_protocol_supported

import rego.v1

# Evaluates the ALPN protocol negotiated during the TLS handshake.
#
# RFC 7301 defines ALPN as the mechanism by which a client and server agree on an
# application protocol. NIST SP 800-52r2 recommends HTTP/2 support for modern deployments.
#
# Decision set:
#   skip — server did not negotiate ALPN (not a failure; just no signal)
#   pass — HTTP/2 ("h2") was negotiated
#   warn — only HTTP/1.1 was negotiated
#   fail — an unknown or empty ALPN value was negotiated

default decision := "skip"
default reason := "alpn_protocol field absent or null — server did not negotiate ALPN"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

has_alpn if {
    input.alpn_protocol != null
}

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "pass" if {
    has_alpn
    input.alpn_protocol == "h2"
}

decision := "warn" if {
    has_alpn
    input.alpn_protocol == "http/1.1"
}

decision := "fail" if {
    has_alpn
    input.alpn_protocol != "h2"
    input.alpn_protocol != "http/1.1"
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "HTTP/2 (h2) negotiated via ALPN — compliant with NIST SP 800-52r2 modern protocol recommendations" if {
    decision == "pass"
}

reason := sprintf("only HTTP/1.1 negotiated via ALPN — HTTP/2 support recommended (NIST SP 800-52r2 §3.1); current value: %q", [input.alpn_protocol]) if {
    decision == "warn"
}

reason := sprintf("unexpected ALPN protocol negotiated: %q — expected \"h2\" or \"http/1.1\"", [input.alpn_protocol]) if {
    decision == "fail"
}
