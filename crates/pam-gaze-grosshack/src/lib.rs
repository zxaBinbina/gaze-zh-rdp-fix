// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::missing_safety_doc)]
#[path = "../../pam-gaze/src/core.rs"]
pub mod core;
pub use core::*;

#[path = "../../pam-gaze/src/auth.rs"]
pub mod auth;
pub use auth::*;

use std::fs::OpenOptions;
use std::io::Write;
use std::os::raw::{c_char, c_int};

pub const DEPRECATION_NOTICE: &str = "\x1b[1;33m[Gaze 提示]\x1b[0m pam_gaze_grosshack.so 已弃用，将在未来版本中移除。\n\
    请将 PAM 配置更新为： pam_gaze.so simultaneous\n\
    运行 'gaze doctor' 检查配置。\n";

pub fn emit_deprecation_notice() {
    if let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") {
        let _ = tty.write_all(DEPRECATION_NOTICE.as_bytes());
    } else {
        eprint!("{DEPRECATION_NOTICE}");
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    emit_deprecation_notice();
    let mut options = unsafe { parse_raw_pam_options(argc, argv) };
    options.mode = PamMode::Simultaneous;
    unsafe { do_authenticate(pamh, flags, options) }
}

pam_success_stubs!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deprecation_notice_contains_expected_guidance() {
        assert!(DEPRECATION_NOTICE.contains("pam_gaze_grosshack.so 已弃用"));
        assert!(DEPRECATION_NOTICE.contains("pam_gaze.so simultaneous"));
        assert!(DEPRECATION_NOTICE.contains("gaze doctor"));
    }
}
