package compliance.dns.caa_records_present

import rego.v1

default decision := "skip"
default reason := "no DNS CAA evidence in input"

# Pass: domain has CAA records with at least one "issue" tag
decision := "pass" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(issue_records) > 0
}

# Warn: domain has CAA records but no "issue" tag (e.g. only iodef)
decision := "warn" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(issue_records) == 0
}

# Fail: no CAA records — any CA can issue certificates for this domain
decision := "fail" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == false
}

issue_records contains r if {
    some r in input.caa_records
    r.tag == "issue"
}

reason := sprintf("CAA records present: %d issue record(s) restrict certificate issuance", [count(issue_records)]) if {
    decision == "pass"
}

reason := "CAA records present but no 'issue' tag — certificate issuance not restricted" if {
    decision == "warn"
}

reason := "no CAA records found — any CA can issue certificates for this domain" if {
    decision == "fail"
}
