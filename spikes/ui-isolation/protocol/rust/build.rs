//! Generates the protocol types from the one schema, and the schema's
//! descriptor set, whose SHA-256 is the handshake's `schema_hash`.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let proto_root = PathBuf::from("../proto");
    let proto = proto_root.join("mesh/ui/v1/spike.proto");
    println!("cargo:rerun-if-changed={}", proto.display());
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    // The Rust types (prost), from the system protoc.
    prost_build::Config::new()
        .compile_protos(&[&proto], &[&proto_root])
        .expect("protoc must compile the schema");

    // The descriptor set the schema hash is taken over. Produced by the
    // same protoc invocation every language's build runs, without source
    // info, so the hash does not depend on comments or layout.
    let protoc = std::env::var("PROTOC").unwrap_or_else(|_| "protoc".into());
    let status = Command::new(protoc)
        .arg(format!("--proto_path={}", proto_root.display()))
        .arg(format!("--descriptor_set_out={}", out.join("schema.bin").display()))
        .arg(&proto)
        .status()
        .expect("protoc must run");
    assert!(status.success(), "protoc failed to write the descriptor set");
}
