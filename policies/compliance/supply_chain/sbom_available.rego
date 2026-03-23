package compliance.supply_chain.sbom_available

import rego.v1

default decision := "skip"
default reason := "supply chain probe not run"

# Pass: SBOM document found at /.well-known/sbom
decision := "pass" if {
    object.get(input, "sbom_found", null) != null
    input.sbom_found == true
}

# Fail: probe ran (sbom_found field present) but no SBOM document found
decision := "fail" if {
    object.get(input, "sbom_found", null) != null
    input.sbom_found == false
}

reason := sprintf(
    "SBOM found at /.well-known/sbom (format: %v, components: %d)",
    [input.sbom_format, input.sbom_component_count]
) if { decision == "pass" }

reason := "No SBOM document found at /.well-known/sbom — EU Cyber Resilience Act requires a machine-readable SBOM" if {
    decision == "fail"
}
