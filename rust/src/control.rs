use crate::*;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn run(command: &str, module: &Path) -> Result<()> {
    let root = Path::new(DATA);
    let store = if command == "initialize" {
        state::Store::initialize(root)?
    } else {
        state::Store::open(root)?
    };
    match command {
        "initialize" | "status" => store.publish_status(module),
        "toggle" => {
            let config = store.toggle()?;
            println!(
                "Status: {}",
                if config.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Fully restart the game for this setting to take effect.");
            store.publish_status(module).map_err(|e| Error {
                message: format!(
                    "Setting saved; module description update failed: {}",
                    e.message
                ),
                ..e
            })
        }
        _ => Err(Error::new("CONTROL_INVALID", "Unknown control command")),
    }
}

/// # Safety
/// The executable supplies two non-null NUL-terminated strings borrowed for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_control(command: *const c_char, module: *const c_char) -> c_int {
    if libc::getuid() != 0 {
        eprintln!("Module control requires root");
        return 1;
    }
    let command = CStr::from_ptr(command).to_str();
    let module = Path::new(std::ffi::OsStr::from_bytes(
        CStr::from_ptr(module).to_bytes(),
    ));
    let result = command
        .map_err(|_| Error::new("CONTROL_INVALID", "Invalid control command"))
        .and_then(|command| run(command, module));
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {}", e.code, e.message);
            log_error(&e);
            1
        }
    }
}
