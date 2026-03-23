package security.semantic.multi_technique_bypass_test

import rego.v1

import data.security.semantic.multi_technique_bypass

test_empty_techniques_passes if {
    result := multi_technique_bypass.decision with input as {
        "bypass_techniques": [],
    }
    result == "pass"
}

test_single_technique_warns if {
    result := multi_technique_bypass.decision with input as {
        "bypass_techniques": ["base64_encoding"],
    }
    result == "warn"
}

test_two_techniques_fails if {
    result := multi_technique_bypass.decision with input as {
        "bypass_techniques": ["base64_encoding", "leetspeak"],
    }
    result == "fail"
}

test_many_techniques_fails if {
    result := multi_technique_bypass.decision with input as {
        "bypass_techniques": ["base64_encoding", "leetspeak", "unicode_homoglyphs", "hex_encoding"],
    }
    result == "fail"
}

test_missing_field_skips if {
    result := multi_technique_bypass.decision with input as {}
    result == "skip"
}
