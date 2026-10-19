fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=logo.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        winresource::WindowsResource::new()
            .set_icon("logo.ico")
            .compile()?;
    }
    Ok(())
}
