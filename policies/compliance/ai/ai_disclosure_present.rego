package compliance.ai.ai_disclosure_present

import rego.v1

default decision := "skip"
default reason := "no AI disclosure evidence collected"

# Pass: at least one disclosure signal present (header or manifest)
decision := "pass" if {
    object.get(input, "has_disclosure_header", null) != null
    input.has_disclosure_header == true
}

decision := "pass" if {
    object.get(input, "has_ai_manifest", null) != null
    input.has_ai_manifest == true
}

# Warn: evidence collected but no disclosure headers or manifest found
decision := "warn" if {
    object.get(input, "has_disclosure_header", null) != null
    input.has_disclosure_header == false
    input.has_ai_manifest == false
}

reason := "AI disclosure header(s) present (X-AI-Generated / X-AI-Model / X-AI-Provider)" if {
    decision == "pass"
    input.has_disclosure_header == true
}
reason := "AI service manifest present at /.well-known/ai-plugin.json" if {
    decision == "pass"
    input.has_disclosure_header == false
    input.has_ai_manifest == true
}
reason := "No AI disclosure headers or manifest found; consumers cannot verify AI provenance" if { decision == "warn" }
