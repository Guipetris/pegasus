package shared.tls.alpn_protocol_supported_test

import rego.v1

import data.shared.tls.alpn_protocol_supported

# ---------------------------------------------------------------------------
# skip: no alpn_protocol field
# ---------------------------------------------------------------------------

test_no_alpn_field_skips if {
    result := alpn_protocol_supported.decision with input as {
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS13_AES_256_GCM_SHA384",
        "certificates": [],
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# skip: alpn_protocol is null
# ---------------------------------------------------------------------------

test_null_alpn_skips if {
    result := alpn_protocol_supported.decision with input as {
        "protocol_version": "TLSv1.3",
        "alpn_protocol": null,
        "certificates": [],
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# pass: h2 negotiated
# ---------------------------------------------------------------------------

test_h2_passes if {
    result := alpn_protocol_supported.decision with input as {
        "protocol_version": "TLSv1.3",
        "alpn_protocol": "h2",
        "certificates": [],
    }
    result == "pass"
}

test_h2_reason if {
    result := alpn_protocol_supported.reason with input as {
        "protocol_version": "TLSv1.3",
        "alpn_protocol": "h2",
        "certificates": [],
    }
    contains(result, "HTTP/2")
    contains(result, "h2")
}

# ---------------------------------------------------------------------------
# warn: http/1.1 only
# ---------------------------------------------------------------------------

test_http11_warns if {
    result := alpn_protocol_supported.decision with input as {
        "protocol_version": "TLSv1.2",
        "alpn_protocol": "http/1.1",
        "certificates": [],
    }
    result == "warn"
}

test_http11_reason_mentions_recommendation if {
    result := alpn_protocol_supported.reason with input as {
        "alpn_protocol": "http/1.1",
        "certificates": [],
    }
    contains(result, "HTTP/2")
}

# ---------------------------------------------------------------------------
# fail: unknown protocol
# ---------------------------------------------------------------------------

test_unknown_alpn_fails if {
    result := alpn_protocol_supported.decision with input as {
        "alpn_protocol": "spdy/3.1",
        "certificates": [],
    }
    result == "fail"
}

test_empty_string_alpn_fails if {
    result := alpn_protocol_supported.decision with input as {
        "alpn_protocol": "",
        "certificates": [],
    }
    result == "fail"
}
