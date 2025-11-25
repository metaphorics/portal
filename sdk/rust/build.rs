use std::io::Result;

fn main() -> Result<()> {
    // Tell Cargo to rerun if proto files change
    println!("cargo:rerun-if-changed=../../portal/core/proto/rdsec/rdsec.proto");
    println!("cargo:rerun-if-changed=../../portal/core/proto/rdverb/rdverb.proto");

    // Compile protobuf files
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(
            &[
                "../../portal/core/proto/rdsec/rdsec.proto",
                "../../portal/core/proto/rdverb/rdverb.proto",
            ],
            &["../../"],
        )?;

    Ok(())
}
