package security.http.robots_sensitive_paths

import rego.v1

# Checks robots.txt for Disallow directives that expose sensitive application
# paths (admin panels, internal APIs, debug surfaces, backup directories, etc.).
#
# Evidence input fields (from WellKnownProbeResult):
#   input.robots_txt.found                 bool
#   input.robots_txt.has_sensitive_paths   bool
#   input.robots_txt.sensitive_paths_found array of strings
#
# Decision logic:
#   skip — no well-known probe evidence in input
#   skip — robots.txt was not found (nothing to evaluate)
#   pass — robots.txt found, no sensitive paths exposed
#   warn — robots.txt found and at least one sensitive path is listed
#
# Note: The presence of a sensitive path in robots.txt does not confirm the
# path is accessible — it confirms its existence is disclosed.  Attackers
# routinely scan robots.txt for target paths.
#
# Standards: OWASP Testing Guide OTG-INFO-001 (Information Gathering)

default decision := "skip"
default reason := "no well-known probe evidence in input"

decision := "skip" if {
    object.get(input, "robots_txt", null) != null
    object.get(input.robots_txt, "found", null) != null
    input.robots_txt.found == false
}

decision := "pass" if {
    object.get(input, "robots_txt", null) != null
    input.robots_txt.found == true
    input.robots_txt.has_sensitive_paths == false
}

decision := "warn" if {
    object.get(input, "robots_txt", null) != null
    input.robots_txt.found == true
    input.robots_txt.has_sensitive_paths == true
}

reason := "robots.txt not found — nothing to evaluate" if {
    decision == "skip"
    object.get(input, "robots_txt", null) != null
}

reason := "robots.txt found — no sensitive application paths exposed via Disallow directives" if {
    decision == "pass"
}

reason := sprintf("robots.txt discloses %d sensitive path(s): %v — consider whether these paths should be publicly known", [count(input.robots_txt.sensitive_paths_found), input.robots_txt.sensitive_paths_found]) if {
    decision == "warn"
}
