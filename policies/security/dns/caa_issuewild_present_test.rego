package security.dns.caa_issuewild_present_test

import rego.v1

import data.security.dns.caa_issuewild_present

test_issuewild_present_passes if {
    result := caa_issuewild_present.decision with input as {
        "has_caa": true,
        "caa_records": [
            {"tag": "issue", "value": "letsencrypt.org"},
            {"tag": "issuewild", "value": "letsencrypt.org"},
        ],
    }
    result == "pass"
}

test_only_issue_tag_warns if {
    result := caa_issuewild_present.decision with input as {
        "has_caa": true,
        "caa_records": [
            {"tag": "issue", "value": "letsencrypt.org"},
        ],
    }
    result == "warn"
}

test_no_caa_skips if {
    result := caa_issuewild_present.decision with input as {
        "has_caa": false,
        "caa_records": [],
    }
    result == "skip"
}

test_no_has_caa_field_skips if {
    result := caa_issuewild_present.decision with input as {}
    result == "skip"
}
