package compliance.dns.caa_iodef_present_test

import rego.v1

import data.compliance.dns.caa_iodef_present

test_iodef_present_passes if {
    result := caa_iodef_present.decision with input as {
        "has_caa": true,
        "caa_records": [
            {"tag": "issue", "value": "letsencrypt.org"},
            {"tag": "iodef", "value": "mailto:security@example.com"},
        ],
    }
    result == "pass"
}

test_no_iodef_warns if {
    result := caa_iodef_present.decision with input as {
        "has_caa": true,
        "caa_records": [
            {"tag": "issue", "value": "letsencrypt.org"},
        ],
    }
    result == "warn"
}

test_no_caa_skips if {
    result := caa_iodef_present.decision with input as {
        "has_caa": false,
        "caa_records": [],
    }
    result == "skip"
}

test_no_has_caa_field_skips if {
    result := caa_iodef_present.decision with input as {}
    result == "skip"
}
