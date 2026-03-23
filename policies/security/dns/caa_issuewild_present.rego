package security.dns.caa_issuewild_present

import rego.v1

default decision := "skip"
default reason := "no DNS CAA evidence in input or no CAA records present"

decision := "pass" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(issuewild_records) > 0
}

decision := "warn" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(issuewild_records) == 0
}

issuewild_records contains r if {
    some r in input.caa_records
    r.tag == "issuewild"
}

reason := "CAA issuewild record present — wildcard certificate issuance is restricted" if { decision == "pass" }
reason := "CAA records present but no issuewild tag — any CA can issue wildcard certificates" if { decision == "warn" }
