package compliance.dns.caa_iodef_present

import rego.v1

default decision := "skip"
default reason := "no DNS CAA evidence in input or no CAA records present"

decision := "pass" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(iodef_records) > 0
}

decision := "warn" if {
    object.get(input, "has_caa", null) != null
    input.has_caa == true
    count(iodef_records) == 0
}

iodef_records contains r if {
    some r in input.caa_records
    r.tag == "iodef"
}

reason := "CAA iodef record present — misissuance incidents will be reported" if { decision == "pass" }
reason := "CAA records present but no iodef tag — certificate misissuance will not be reported" if { decision == "warn" }
