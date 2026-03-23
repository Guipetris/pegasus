package compliance.tls.extended_key_usage_server_auth_test

import rego.v1

import data.compliance.tls.extended_key_usage_server_auth

# ---------------------------------------------------------------------------
# skip: no certificates
# ---------------------------------------------------------------------------

test_no_certs_skips if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [],
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# skip: EKU extension absent (empty list)
# ---------------------------------------------------------------------------

test_no_eku_extension_skips if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=legacy.example.com",
            "is_ca": false,
            "extended_key_usage": [],
        }],
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# skip: leaf cert is a CA (CA certs don't need serverAuth)
# ---------------------------------------------------------------------------

test_ca_cert_skips if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=My Root CA",
            "is_ca": true,
            "extended_key_usage": [],
        }],
    }
    result == "skip"
}

# ---------------------------------------------------------------------------
# pass: serverAuth present
# ---------------------------------------------------------------------------

test_server_auth_passes if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "is_ca": false,
            "extended_key_usage": ["serverAuth"],
        }],
    }
    result == "pass"
}

# pass: serverAuth among multiple EKUs
test_server_auth_among_multiple_passes if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "is_ca": false,
            "extended_key_usage": ["serverAuth", "clientAuth"],
        }],
    }
    result == "pass"
}

test_pass_reason_mentions_server_auth if {
    result := extended_key_usage_server_auth.reason with input as {
        "certificates": [{
            "subject": "CN=example.com",
            "is_ca": false,
            "extended_key_usage": ["serverAuth"],
        }],
    }
    contains(result, "serverAuth")
}

# ---------------------------------------------------------------------------
# fail: EKU present but serverAuth missing
# ---------------------------------------------------------------------------

test_client_auth_only_fails if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=clientonly.example.com",
            "is_ca": false,
            "extended_key_usage": ["clientAuth"],
        }],
    }
    result == "fail"
}

test_code_signing_only_fails if {
    result := extended_key_usage_server_auth.decision with input as {
        "certificates": [{
            "subject": "CN=signing.example.com",
            "is_ca": false,
            "extended_key_usage": ["codeSigning"],
        }],
    }
    result == "fail"
}

test_fail_reason_mentions_present_ekus if {
    result := extended_key_usage_server_auth.reason with input as {
        "certificates": [{
            "subject": "CN=clientonly.example.com",
            "is_ca": false,
            "extended_key_usage": ["clientAuth"],
        }],
    }
    contains(result, "clientAuth")
}
