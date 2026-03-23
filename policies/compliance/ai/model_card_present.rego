package compliance.ai.model_card_present

import rego.v1

default decision := "skip"
default reason := "no model card evidence collected"

# Pass: model card found and fully complete (all 4 required fields present)
decision := "pass" if {
    object.get(input, "model_card_found", null) != null
    input.model_card_found == true
    input.has_intended_use == true
    input.has_limitations == true
    input.has_training_data_summary == true
    input.has_ethical_considerations == true
}

# Warn: model card found but one or more required fields missing
decision := "warn" if {
    object.get(input, "model_card_found", null) != null
    input.model_card_found == true
    input.completeness_score < 1.0
}

# Fail: evidence was collected but no model card was found
decision := "fail" if {
    object.get(input, "model_card_found", null) != null
    input.model_card_found == false
}

reason := "AI model card present and complete (ISO 42001 §6.1.2, EU AI Act Art. 13)" if { decision == "pass" }
reason := "AI model card found but incomplete — one or more required fields missing" if { decision == "warn" }
reason := "AI model card not found at /.well-known/ai-model-card.json" if { decision == "fail" }
