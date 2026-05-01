fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../assets/icons/mkpe_app.ico");
        res.set("ProductName", "MKPE");
        res.set("FileDescription", "Morse-Kirby Provenance Engine");
        res.compile().unwrap();
    }
}



