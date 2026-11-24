// Generates the Rust client and server for Proton Bridge's frontend gRPC
// service from the vendored proto. protoc is supplied by protoc-bin-vendored
// so no system protoc is needed, on a developer machine or in CI.

use std::path::PathBuf;

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is unavailable");
    // SAFETY: single-threaded build script, set before tonic-build reads it.
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }

    let proto_root = PathBuf::from("proto");
    let bridge_proto = proto_root.join("bridge.proto");

    println!("cargo:rerun-if-changed={}", bridge_proto.display());
    println!("cargo:rerun-if-changed=proto/google/protobuf/empty.proto");
    println!("cargo:rerun-if-changed=proto/google/protobuf/wrappers.proto");

    tonic_build::configure()
        .build_client(true)
        // The server is generated so the crate's own tests can stand up a
        // mock Bridge over TLS and exercise the real client end to end.
        .build_server(true)
        // Generate the google.protobuf well-known types into this crate so it
        // depends on nothing for them and Empty stays a real message.
        .compile_well_known_types(true)
        .compile_protos(&[bridge_proto], &[proto_root])
        .expect("failed to compile Proton Bridge proto");
}
