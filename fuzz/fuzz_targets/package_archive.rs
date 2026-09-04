#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let mut file = tempfile::NamedTempFile::new().expect("temporary fuzz input");
    file.write_all(data).expect("write fuzz input");
    let _ = arc::package::inspect(file.path());
});
