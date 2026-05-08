fn main() {
    cc::Build::new()
        .cpp(true)
        .file("src/injector.cpp")
        .define("_CRT_SECURE_NO_WARNINGS", None) // Убираем ворнинги MSVC
        .compile("injector_logic");

    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=shell32");
    println!("cargo:rustc-link-lib=ole32");
}