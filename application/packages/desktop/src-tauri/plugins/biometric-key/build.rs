fn main() {
    tauri_plugin::Builder::new(&["create", "open", "delete"])
        .android_path("android")
        .build();
}
