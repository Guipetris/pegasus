use pegasus_types::types::{
    AttestationRecord, ComplianceReport, EvidenceEnvelope, PolicyEvaluationResult,
};
use schemars::schema_for;
use std::fs;
use std::path::Path;

fn main() {
    let schemas_dir = Path::new("schemas");
    fs::create_dir_all(schemas_dir).expect("failed to create schemas directory");

    write_schema::<EvidenceEnvelope>(schemas_dir, "evidence_envelope.schema.json");
    write_schema::<AttestationRecord>(schemas_dir, "attestation_record.schema.json");
    write_schema::<PolicyEvaluationResult>(schemas_dir, "policy_evaluation_result.schema.json");
    write_schema::<ComplianceReport>(schemas_dir, "compliance_report.schema.json");

    println!("Schemas generated in {}", schemas_dir.display());
}

fn write_schema<T: schemars::JsonSchema>(dir: &Path, filename: &str) {
    let schema = schema_for!(T);
    let json = serde_json::to_string_pretty(&schema).expect("failed to serialize schema");
    fs::write(dir.join(filename), json).expect("failed to write schema file");
}
