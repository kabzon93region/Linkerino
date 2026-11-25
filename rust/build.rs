fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=assets/linkerino.ico");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let version = if version.matches('.').count() >= 3 { version } else { format!("{version}.0") };
    let mut resource = winres::WindowsResource::new();
    resource.set_icon("assets/linkerino.ico");
    resource.set("ProductName", "Linkerino");
    resource.set("FileDescription", "Linkerino - move a folder and leave a symlink");
    resource.set("OriginalFilename", "Linkerino.exe");
    resource.set("CompanyName", "kabzon93region");
    resource.set("LegalCopyright", "MIT License");
    resource.set("FileVersion", &version);
    resource.set("ProductVersion", &version);
    if let Err(error) = resource.compile() {
        panic!("failed to compile the Windows resources: {error}");
    }
}
