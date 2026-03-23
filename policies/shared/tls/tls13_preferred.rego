package shared.tls.tls13_preferred

import rego.v1

# Skip when protocol_version is not present in input.
# Pass for TLSv1.3, warn for TLSv1.2, fail for anything older.

default decision := "skip"
default reason := "insufficient input: protocol_version not present"

# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------

decision := "pass" if {
    input.protocol_version == "TLSv1.3"
}

decision := "warn" if {
    input.protocol_version == "TLSv1.2"
}

decision := "fail" if {
    input.protocol_version
    input.protocol_version != "TLSv1.3"
    input.protocol_version != "TLSv1.2"
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "TLS 1.3 is in use — optimal protocol version" if {
    decision == "pass"
}

reason := "TLS 1.2 is in use — acceptable but TLS 1.3 is preferred" if {
    decision == "warn"
}

reason := "deprecated TLS protocol version in use — upgrade to TLS 1.2 or TLS 1.3 immediately" if {
    decision == "fail"
}
