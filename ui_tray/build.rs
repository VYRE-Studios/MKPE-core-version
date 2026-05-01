fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../assets/icons/mkpe_app.ico");
        res.set("ProductName", "MKPE Tray");
        res.set("FileDescription", "Morse-Kirby Provenance Engine");
        res.set("CompanyName", "Morse-Kirby Development");
        res.compile().unwrap();
    }
}



