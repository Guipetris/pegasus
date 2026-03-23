package security.tls.weak_cipher_detection

import rego.v1

# CRITICAL: Skip gracefully when input fields are missing.
# Existing test fixtures only have certificates — no protocol_version/cipher_suite.
# This policy only activates when TLS probe populates those fields.

default decision := "skip"
default reason := "insufficient input: protocol_version or cipher_suite not present"

# ---------------------------------------------------------------------------
# Weak cipher / algorithm sets
# ---------------------------------------------------------------------------

weak_cipher_patterns := {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}

cipher_is_weak if {
    some pattern in weak_cipher_patterns
    contains(input.cipher_suite, pattern)
}

# ---------------------------------------------------------------------------
# Protocol version helpers
# ---------------------------------------------------------------------------

# Parse the numeric version from strings like "TLSv1.0", "TLSv1.2", "TLSv1.3"
# We compare as decimals: 1.0 < 1.1 < 1.2 < 1.3
protocol_version_ok if {
    input.protocol_version == "TLSv1.2"
}

protocol_version_ok if {
    input.protocol_version == "TLSv1.3"
}

protocol_version_weak if {
    not protocol_version_ok
}

# ---------------------------------------------------------------------------
# Key strength helpers
# ---------------------------------------------------------------------------

# RSA key is critically weak (< 1024 bits) — hard fail
rsa_key_critically_weak if {
    some cert in input.certificates
    cert.key_algorithm == "RSA"
    cert.key_size < 1024
}

# RSA key is in the warn zone (1024–2047 bits)
rsa_key_warn if {
    not rsa_key_critically_weak
    some cert in input.certificates
    cert.key_algorithm == "RSA"
    cert.key_size < 2048
}

# EC key is weak (< 256 bits)
ec_key_weak if {
    some cert in input.certificates
    cert.key_algorithm == "EC"
    cert.key_size < 256
}

# ---------------------------------------------------------------------------
# Decision rules (only evaluate when both required fields are present)
# ---------------------------------------------------------------------------

# fail: insecure protocol, weak cipher, critically weak RSA key, or weak EC key
decision := "fail" if {
    input.protocol_version
    input.cipher_suite
    protocol_version_weak
}

decision := "fail" if {
    input.protocol_version
    input.cipher_suite
    cipher_is_weak
}

decision := "fail" if {
    input.protocol_version
    input.cipher_suite
    rsa_key_critically_weak
}

decision := "fail" if {
    input.protocol_version
    input.cipher_suite
    ec_key_weak
}

# warn: protocol ok, no weak ciphers, but RSA key in warn zone (1024–2047)
decision := "warn" if {
    input.protocol_version
    input.cipher_suite
    protocol_version_ok
    not cipher_is_weak
    not rsa_key_critically_weak
    not ec_key_weak
    rsa_key_warn
}

# pass: all checks green
decision := "pass" if {
    input.protocol_version
    input.cipher_suite
    protocol_version_ok
    not cipher_is_weak
    not rsa_key_critically_weak
    not rsa_key_warn
    not ec_key_weak
}

# ---------------------------------------------------------------------------
# Reason messages
# ---------------------------------------------------------------------------

reason := "TLS configuration is strong: protocol, cipher suite, and key sizes all pass" if {
    decision == "pass"
}

reason := "insecure protocol version detected (requires TLS 1.2 or higher)" if {
    decision == "fail"
    protocol_version_weak
    not cipher_is_weak
    not rsa_key_critically_weak
    not ec_key_weak
}

reason := "weak cipher suite detected in cipher suite name" if {
    decision == "fail"
    cipher_is_weak
}

reason := "RSA key size critically weak (< 1024 bits)" if {
    decision == "fail"
    rsa_key_critically_weak
    not cipher_is_weak
    not protocol_version_weak
}

reason := "EC key size weak (< 256 bits)" if {
    decision == "fail"
    ec_key_weak
    not cipher_is_weak
    not protocol_version_weak
    not rsa_key_critically_weak
}

reason := "RSA key size in warn zone (1024–2047 bits): consider upgrading to 2048+" if {
    decision == "warn"
}
