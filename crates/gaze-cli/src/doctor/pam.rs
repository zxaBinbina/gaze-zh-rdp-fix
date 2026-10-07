// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

pub(super) fn pam_search_dirs() -> BTreeSet<PathBuf> {
    let mut dirs = BTreeSet::from([
        PathBuf::from("/lib/security"),
        PathBuf::from("/lib64/security"),
        PathBuf::from("/usr/lib/security"),
        PathBuf::from("/usr/lib64/security"),
    ]);

    for base in ["/lib", "/usr/lib"] {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let security = entry.path().join("security");
            if security.is_dir() {
                dirs.insert(security);
            }
        }
    }
    dirs
}

/// Distributions that load the modules from an absolute path, such as NixOS
/// pointing at the store, never populate a system module directory.
pub(super) fn find_pam_modules() -> BTreeSet<PathBuf> {
    pam_search_dirs()
        .into_iter()
        .flat_map(|dir| PAM_MODULES.map(|module| dir.join(module)))
        .chain(pam_files().iter().flat_map(|(_, contents)| {
            contents
                .lines()
                .flat_map(pam_line_module_paths)
                .collect::<Vec<_>>()
        }))
        .filter(|path| path.exists())
        .collect()
}

pub(super) fn pam_line_has_reference(line: &str) -> bool {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return false;
    }
    line.split_ascii_whitespace().any(|token| {
        PAM_MODULES
            .iter()
            .any(|module| token == *module || token.ends_with(&format!("/{module}")))
    })
}

pub(super) const PAM_INCLUDE_DIRECTIVES: [&str; 2] = ["include", "substack"];

pub(super) fn pam_include_target(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or_default();
    let mut tokens = line.split_ascii_whitespace();
    let first = tokens.next()?;
    if first == "@include" {
        return tokens.next();
    }
    let control = tokens.next()?;
    if PAM_INCLUDE_DIRECTIVES.contains(&control) {
        tokens.next()
    } else {
        None
    }
}

/// Whether a service ends up loading a Gaze module, following `include`/`substack` into the
/// shared stacks Debian and Fedora wire Gaze into rather than naming it per service.
pub(super) fn pam_service_reaches_gaze(service: &str, depth: u8) -> bool {
    let Some(contents) = read_pam_service(&format!("/etc/pam.d/{service}")) else {
        return false;
    };
    if contents.lines().any(pam_line_has_reference) {
        return true;
    }
    depth > 0
        && contents
            .lines()
            .filter_map(pam_include_target)
            .any(|target| pam_service_reaches_gaze(target, depth - 1))
}

pub(super) fn pam_line_module_paths(line: &str) -> Vec<PathBuf> {
    line.split('#')
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .filter(|token| {
            token.starts_with('/')
                && PAM_MODULES
                    .iter()
                    .any(|module| token.ends_with(&format!("/{module}")))
        })
        .map(PathBuf::from)
        .collect()
}

pub(super) fn pam_files() -> Vec<(PathBuf, String)> {
    let Ok(entries) = fs::read_dir("/etc/pam.d") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let contents = fs::read_to_string(&path).ok()?;
            Some((path, contents))
        })
        .collect()
}

pub(super) fn ownership_is_unsafe(uid: u32, mode: u32) -> bool {
    uid != 0 || mode & 0o022 != 0
}

pub(super) fn insecurely_owned<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Vec<String> {
    paths
        .into_iter()
        .filter_map(|path| {
            let metadata = fs::metadata(path).ok()?;
            ownership_is_unsafe(metadata.uid(), metadata.mode()).then(|| path.display().to_string())
        })
        .collect()
}

/// `/lib` is a symlink to `/usr/lib` on merged-usr systems, so the same unit file appears
/// under both prefixes; report it once, under the name it was first listed with.
pub(super) fn dedup_by_target(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| {
            let target = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            seen.insert(target)
        })
        .collect()
}

pub(super) fn installed_privileged_files() -> Vec<PathBuf> {
    dedup_by_target(
        PRIVILEGED_FILES
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect(),
    )
}

pub(super) fn check_privileged_files(report: &mut Report) {
    let files = installed_privileged_files();
    if files.is_empty() {
        return;
    }

    let writable = insecurely_owned(&files);
    if writable.is_empty() {
        report.pass(
            "服务文件权限",
            "systemd 单元、DBus 策略和 polkit 操作由 root 所有，且组和其他用户不可写",
        );
    } else {
        report.error(
            "服务文件权限",
            format!(
                "所属组中的任何用户都能让 gazed 运行其代码或自行授予访问权限：{}",
                writable.join(", ")
            ),
            "对每个文件运行 `sudo chown root:root <file>` 和 `sudo chmod 644 <file>`，或通过软件包管理器恢复这些文件。",
        );
    }
}

pub(super) fn find_pam_references() -> Vec<PathBuf> {
    pam_files()
        .into_iter()
        .filter_map(|(path, contents)| contents.lines().any(pam_line_has_reference).then_some(path))
        .collect()
}

pub(super) const PAM_ORDERING_COMPETITORS: [&str; 2] = ["pam_unix.so", "pam_fprintd.so"];
pub(super) const PAM_PASSWORD_MODULE: &str = "pam_unix.so";

pub(super) fn pam_line_is_retry(line: &str) -> bool {
    pam_line_has_reference(line)
        && line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_ascii_whitespace()
            .any(|token| token == "retry")
}

pub(super) fn pam_auth_lines(contents: &str) -> Vec<&str> {
    contents
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| matches!(line.split_ascii_whitespace().next(), Some("auth" | "-auth")))
        .collect()
}

pub(super) fn find_misplaced_retry_entry(contents: &str) -> bool {
    let auth_lines = pam_auth_lines(contents);
    let Some(retry_idx) = auth_lines.iter().position(|line| pam_line_is_retry(line)) else {
        return false;
    };
    !auth_lines[..retry_idx]
        .iter()
        .any(|line| line.contains(PAM_PASSWORD_MODULE))
}

/// Returns competing auth modules (password, fingerprint) that appear earlier
/// in the `auth` stack than Gaze, which stalls face auth behind their prompts.
pub(super) fn find_pam_ordering_conflicts(contents: &str) -> Vec<&'static str> {
    let auth_lines: Vec<&str> = contents
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| line.split_ascii_whitespace().next() == Some("auth"))
        .collect();

    let Some(gaze_idx) = auth_lines
        .iter()
        .position(|line| pam_line_has_reference(line) && !pam_line_is_retry(line))
    else {
        return Vec::new();
    };

    PAM_ORDERING_COMPETITORS
        .into_iter()
        .filter(|module| {
            auth_lines[..gaze_idx]
                .iter()
                .any(|line| line.contains(module))
        })
        .collect()
}

pub(super) fn check_pam(report: &mut Report) {
    let modules = find_pam_modules();
    let installed = modules
        .iter()
        .any(|path| path.file_name().is_some_and(|name| name == PAM_MODULES[0]));

    if installed {
        report.pass("PAM 模块", "pam_gaze.so 已安装");
    } else {
        report.error(
            "PAM 模块",
            "PAM 无法在模块加载路径中找到 pam_gaze.so",
            "启用 PAM 认证前，请重新安装 Gaze 基础软件包。",
        );
    }

    let insecure = insecurely_owned(&modules);
    if !modules.is_empty() {
        if insecure.is_empty() {
            report.pass("PAM 权限", "已安装的模块由 root 所有，且组和其他用户不可写");
        } else {
            report.error(
                "PAM 权限",
                format!("所有权或写入权限不安全：{}", insecure.join(", ")),
                "通过软件包管理器恢复这些文件；不要使用可被写入的 PAM 模块。",
            );
        }
    }

    let references = find_pam_references();
    if references.is_empty() {
        report.warning(
            "PAM 认证栈",
            "没有启用的 /etc/pam.d 文件引用 Gaze 模块",
            "如需登录、sudo 或锁屏认证，请参照您的发行版的 PAM 指南。",
        );
    } else {
        let names = references
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ");
        report.pass("PAM 认证栈", format!("以下服务引用了 Gaze：{names}"));

        let writable = insecurely_owned(&references);
        if writable.is_empty() {
            report.pass(
                "PAM 认证栈权限",
                "引用 Gaze 的服务文件由 root 所有，且组和其他用户不可写",
            );
        } else {
            report.error(
                "PAM 认证栈权限",
                format!(
                    "所属组中的任何用户都能让 Gaze 运行其代码：{}",
                    writable.join(", ")
                ),
                "通过软件包管理器恢复这些文件；不要使用可被写入的 PAM 配置。",
            );
        }

        let deprecated_refs: Vec<_> = pam_files()
            .into_iter()
            .filter(|(_, contents)| {
                contents.lines().any(|line| {
                    let line = line.split('#').next().unwrap_or_default().trim();
                    line.split_ascii_whitespace().any(|token| {
                        token == "pam_gaze_grosshack.so"
                            || token.ends_with("/pam_gaze_grosshack.so")
                    })
                })
            })
            .map(|(path, _)| path)
            .collect();

        if !deprecated_refs.is_empty() {
            let paths = deprecated_refs
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            report.warning(
                "已弃用的 PAM 模块",
                format!("以下文件引用了 pam_gaze_grosshack.so：{paths}"),
                "将这些文件中的 'pam_gaze_grosshack.so' 替换为 'pam_gaze.so simultaneous'。pam_gaze_grosshack.so 将在未来版本中移除。",
            );
        }

        for path in &references {
            let Ok(contents) = fs::read_to_string(path) else {
                continue;
            };
            let conflicts = find_pam_ordering_conflicts(&contents);
            if !conflicts.is_empty() {
                report.warning(
                    "PAM 顺序",
                    format!(
                        "{} 在 {} 之后运行（{}），因此只有完成这些提示后才会尝试人脸认证",
                        PAM_MODULES.join("/"),
                        conflicts.join(", "),
                        path.display()
                    ),
                    "重新运行 `sudo pam-auth-update --package`（Debian/Ubuntu），或将 Gaze 行移至 pam_unix.so/pam_fprintd.so 之前。",
                );
            }

            if find_misplaced_retry_entry(&contents) {
                report.warning(
                    "PAM 重试顺序",
                    format!(
                        "pam_gaze.so retry 在 {} 之前运行（{}），因此密码被拒绝后无法执行该模块",
                        PAM_PASSWORD_MODULE,
                        path.display()
                    ),
                    "将 `pam_gaze.so retry` 行移至 pam_unix.so 之后，或重新运行 `sudo pam-auth-update --package`（Debian/Ubuntu）。",
                );
            }
        }

        check_elevation_pam(report);
        check_polkit_pam(report);
    }
}

pub(super) fn shared_stack_hint_for(os_release: &str) -> &'static str {
    let os_release = os_release.to_ascii_lowercase();
    if os_release.contains("suse") {
        "运行 `sudo pam-config --add --gaze`，然后运行 `sudo pam-config --update`，并确认 /etc/pam.d/common-auth 中包含 pam_gaze.so。参见 https://gaze.gundulabs.com/guide/pam"
    } else if ["fedora", "rhel", "centos"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "运行 `sudo authselect select gaze with-silent-lastlog --force`。参见 https://gaze.gundulabs.com/guide/pam"
    } else if ["debian", "ubuntu"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "运行 `sudo pam-auth-update --package` 并启用 Gaze 配置。参见 https://gaze.gundulabs.com/guide/pam"
    } else if ["arch", "manjaro", "omarchy"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "在 /etc/pam.d/sudo 的首个 auth 行之前添加 'auth        sufficient    pam_gaze.so'。参见 https://gaze.gundulabs.com/guide/pam"
    } else {
        "在共享认证栈（/etc/pam.d/system-auth，openSUSE 为 /etc/pam.d/common-auth）的首个 auth 行之前添加 'auth        sufficient    pam_gaze.so'。参见 https://gaze.gundulabs.com/guide/pam"
    }
}

pub(super) fn shared_stack_hint() -> &'static str {
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    shared_stack_hint_for(&os_release)
}

pub(super) fn check_elevation_pam(report: &mut Report) {
    if read_pam_service(&format!("/etc/pam.d/{ELEVATION_PAM_SERVICE}")).is_none() {
        return;
    }
    if pam_service_reaches_gaze(ELEVATION_PAM_SERVICE, 2) {
        report.pass(
            "提权 PAM",
            format!("{ELEVATION_PAM_SERVICE} 服务会调用 Gaze 模块"),
        );
    } else if Path::new(PAM_SUDO_OPTOUT_PATH).exists() {
        report.off(
            "提权 PAM",
            format!("已停用 {ELEVATION_PAM_SERVICE} 的人脸认证，终端提权始终要求输入密码"),
            format!(
                "重新启用：`sudo rm {PAM_SUDO_OPTOUT_PATH}`。{}",
                shared_stack_hint()
            ),
        );
    } else {
        report.warning(
            "提权 PAM",
            format!("{ELEVATION_PAM_SERVICE} 服务未调用 Gaze 模块，终端提权会直接使用密码认证栈"),
            shared_stack_hint(),
        );
    }
}

pub(super) const SUDO_TARGET_OPTIONS: [&str; 3] = ["targetpw", "rootpw", "runaspw"];
pub(super) const SUSE_VENDOR_SUDOERS: &str = "/usr/etc/sudoers";
pub(super) const ADMIN_SUDOERS: &str = "/etc/sudoers";
pub(super) const SUSE_SELF_AUTH_DROPINS: [&str; 4] = [
    "/etc/sudoers.d/50-wheel-auth-self",
    "/usr/etc/sudoers.d/50-wheel-auth-self",
    "/etc/sudoers.d/50-sudo-auth-self",
    "/usr/etc/sudoers.d/50-sudo-auth-self",
];

pub(super) enum SudoPolicy {
    AuthenticatesInvoker,
    AuthenticatesTarget(&'static str),
    ProbablyTargetPw,
    Unknown,
}

pub(super) fn sudo_target_auth_option(listing: &str) -> Option<&'static str> {
    let mut entries = String::new();
    let mut in_defaults = false;
    for line in listing.lines() {
        if line.starts_with("Matching Defaults entries") {
            in_defaults = true;
            continue;
        }
        if in_defaults {
            if line.trim().is_empty() {
                break;
            }
            entries.push_str(line);
            entries.push(',');
        }
    }
    entries.split(',').map(str::trim).find_map(|entry| {
        SUDO_TARGET_OPTIONS
            .iter()
            .copied()
            .find(|option| entry == *option)
    })
}

pub(super) fn suse_self_auth_dropin_present() -> Option<bool> {
    let mut present = false;
    for path in SUSE_SELF_AUTH_DROPINS {
        match fs::symlink_metadata(path) {
            Ok(_) => present = true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    Some(present)
}

pub(super) fn sudo_policy(username: &str) -> SudoPolicy {
    if running_as_root() {
        return match command_output_env(
            "sudo",
            &["-n", "-l", "-U", username],
            &[("LC_ALL", OsStr::new("C"))],
        ) {
            Ok((true, listing)) => match sudo_target_auth_option(&listing) {
                Some(option) => SudoPolicy::AuthenticatesTarget(option),
                None => SudoPolicy::AuthenticatesInvoker,
            },
            _ => SudoPolicy::Unknown,
        };
    }
    let vendor_default_in_force =
        Path::new(SUSE_VENDOR_SUDOERS).exists() && !Path::new(ADMIN_SUDOERS).exists();
    match suse_self_auth_dropin_present() {
        Some(false) if vendor_default_in_force => SudoPolicy::ProbablyTargetPw,
        _ => SudoPolicy::Unknown,
    }
}

pub(super) fn os_release_is_suse() -> bool {
    fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("suse")
}

pub(super) fn check_sudo_policy(report: &mut Report, username: &str) {
    if read_pam_service(&format!("/etc/pam.d/{ELEVATION_PAM_SERVICE}")).is_none() {
        return;
    }
    report_sudo_policy(
        report,
        username,
        sudo_policy(username),
        os_release_is_suse(),
    );
}

pub(super) fn report_sudo_policy(
    report: &mut Report,
    username: &str,
    policy: SudoPolicy,
    suse: bool,
) {
    const NAME: &str = "sudo 策略";
    match policy {
        SudoPolicy::AuthenticatesInvoker => report.pass(
            NAME,
            format!(
                "sudo 认证的用户为 {username}，其录入的人脸可用于终端提权"
            ),
        ),
        SudoPolicy::AuthenticatesTarget(option) => {
            let fix = if suse {
                format!(
                    "openSUSE 默认使用此设置。可通过 `sudo zypper install sudo-policy-wheel-auth-self` 让 `wheel` 成员认证自己的身份，或使用 `visudo` 删除 `Defaults {option}`。"
                )
            } else {
                format!(
                    "使用 `visudo` 删除 `Defaults {option}`，或通过 `Defaults:%wheel !{option}` 为管理员组设置例外。"
                )
            };
            report.warning(
                NAME,
                format!(
                    "sudo 配置了 `Defaults {option}`，因此它认证目标用户（root），不会使用 {username} 已录入的人脸"
                ),
                fix,
            );
        }
        SudoPolicy::ProbablyTargetPw => report.warning(
            NAME,
            format!(
                "openSUSE 的默认 sudo 策略（`Defaults targetpw`）认证的是 root，而非 {username}，且未安装为 `wheel` 设置例外的配置"
            ),
            "运行 `sudo gaze doctor` 根据最终策略确认，然后运行 `sudo zypper install sudo-policy-wheel-auth-self`。",
        ),
        SudoPolicy::Unknown => {}
    }
}

pub(super) fn check_polkit_pam(report: &mut Report) {
    if read_pam_service(POLKIT_PAM_FILE).is_none() {
        return;
    }
    if pam_service_reaches_gaze("polkit-1", 2) {
        report.pass("Polkit PAM", "polkit-1 服务会调用 Gaze 模块");
    } else {
        report.warning(
            "Polkit PAM",
            "polkit-1 服务未调用 Gaze 模块，图形认证提示会直接使用密码认证栈",
            format!(
                "在 {POLKIT_PAM_FILE} 的首个 auth 行之前添加 'auth        sufficient    pam_gaze.so'；如文件不存在，先将 {VENDOR_PAM_DIR}/polkit-1 复制到该位置，然后重启 polkit。参见 https://gaze.gundulabs.com/guide/pam"
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_password_default_is_read_from_the_resolved_sudo_listing() {
        let listing = "Matching Defaults entries for alice on host:\n    always_set_home, \
                       env_reset, env_keep=\"LANG LC_ADDRESS\", !insults,\n    \
                       secure_path=\"/usr/sbin:/usr/bin:/sbin:/bin\", targetpw\n\nUser alice \
                       may run the following commands on host:\n    (ALL) ALL\n";
        assert_eq!(sudo_target_auth_option(listing), Some("targetpw"));
        assert_eq!(
            sudo_target_auth_option(&listing.replace("targetpw", "!targetpw")),
            None,
            "a negated option means the invoking user is authenticated"
        );
        assert_eq!(
            sudo_target_auth_option(&listing.replace("targetpw", "rootpw")),
            Some("rootpw")
        );
        assert_eq!(
            sudo_target_auth_option(
                "User alice may run the following commands on host:\n    targetpw\n"
            ),
            None,
            "only the Defaults block is consulted"
        );
    }

    #[test]
    fn sudo_policy_is_only_a_warning_and_names_the_distribution_remedy() {
        let reported = |policy, suse| {
            let mut report = Report::default();
            report_sudo_policy(&mut report, "alice", policy, suse);
            report
                .checks
                .into_iter()
                .find(|check| check.name == "sudo 策略")
        };

        let check = reported(SudoPolicy::AuthenticatesInvoker, true).unwrap();
        assert_eq!(check.level, Level::Pass);

        let check = reported(SudoPolicy::AuthenticatesTarget("targetpw"), true).unwrap();
        assert_eq!(check.level, Level::Warning);
        assert!(
            check
                .fix
                .unwrap_or_default()
                .contains("sudo-policy-wheel-auth-self")
        );

        let check = reported(SudoPolicy::AuthenticatesTarget("rootpw"), false).unwrap();
        assert_eq!(check.level, Level::Warning);
        assert!(check.fix.unwrap_or_default().contains("visudo"));

        let check = reported(SudoPolicy::ProbablyTargetPw, true).unwrap();
        assert_eq!(check.level, Level::Warning);
        assert!(
            check.fix.unwrap_or_default().contains("sudo gaze doctor"),
            "an unprivileged guess asks for confirmation before a package install"
        );

        assert!(reported(SudoPolicy::Unknown, false).is_none());
    }

    #[test]
    fn pam_include_targets_are_read_from_both_include_forms() {
        assert_eq!(
            pam_include_target("auth       include      system-auth"),
            Some("system-auth")
        );
        assert_eq!(
            pam_include_target("auth       substack     password-auth"),
            Some("password-auth")
        );
        assert_eq!(
            pam_include_target("@include common-auth"),
            Some("common-auth")
        );
        assert_eq!(
            pam_include_target("auth        sufficient    pam_gaze.so"),
            None
        );
        assert_eq!(pam_include_target("# auth include system-auth"), None);
        assert_eq!(pam_include_target(""), None);
    }

    #[test]
    fn shared_stack_remedies_use_the_tool_that_owns_the_stack() {
        for (os_release, tool) in [
            ("ID=opensuse-tumbleweed\nID_LIKE=suse\n", "pam-config"),
            ("ID=fedora\n", "authselect"),
            ("ID=ubuntu\nID_LIKE=debian\n", "pam-auth-update"),
            ("ID=omarchy\nID_LIKE=arch\n", "/etc/pam.d/sudo"),
            ("ID=void\n", "/etc/pam.d/system-auth"),
        ] {
            let hint = shared_stack_hint_for(os_release);
            assert!(hint.contains(tool), "{hint:?} does not name {tool}");
        }
    }

    #[test]
    fn root_owned_and_unwritable_is_the_only_safe_ownership() {
        assert!(!ownership_is_unsafe(0, 0o644));
        assert!(!ownership_is_unsafe(0, 0o755));
        assert!(!ownership_is_unsafe(0, 0o600));
    }

    #[test]
    fn group_or_world_writable_privileged_files_are_rejected() {
        assert!(ownership_is_unsafe(0, 0o664), "group-writable");
        assert!(ownership_is_unsafe(0, 0o666), "world-writable");
        assert!(ownership_is_unsafe(0, 0o646), "other-writable");
        assert!(ownership_is_unsafe(1000, 0o644), "not owned by root");
    }

    #[test]
    fn absent_privileged_files_are_not_reported() {
        assert!(
            installed_privileged_files()
                .iter()
                .all(|path| path.exists())
        );
    }

    #[test]
    fn two_spellings_of_one_directory_collapse_to_the_first() {
        let aliased = dedup_by_target(vec![
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/./lib"),
            PathBuf::from("/usr/lib/../lib"),
        ]);
        assert_eq!(aliased, vec![PathBuf::from("/usr/lib")]);
    }

    #[test]
    fn paths_that_do_not_resolve_are_deduplicated_literally() {
        let distinct = dedup_by_target(vec![
            PathBuf::from("/gaze-doctor-absent-a"),
            PathBuf::from("/gaze-doctor-absent-b"),
            PathBuf::from("/gaze-doctor-absent-a"),
        ]);
        assert_eq!(
            distinct,
            vec![
                PathBuf::from("/gaze-doctor-absent-a"),
                PathBuf::from("/gaze-doctor-absent-b")
            ]
        );
    }

    #[test]
    fn pam_line_module_paths_collects_absolute_module_paths() {
        assert_eq!(
            pam_line_module_paths(
                "auth       [success=done default=bad]   /nix/store/abc-gaze-0.2.7/lib/security/pam_gaze.so"
            ),
            vec![PathBuf::from(
                "/nix/store/abc-gaze-0.2.7/lib/security/pam_gaze.so"
            )]
        );
        assert_eq!(
            pam_line_module_paths(
                "auth sufficient /nix/store/abc-gaze/lib/security/pam_gaze.so simultaneous"
            ),
            vec![PathBuf::from(
                "/nix/store/abc-gaze/lib/security/pam_gaze.so"
            )]
        );
        assert_eq!(
            pam_line_module_paths(
                "auth sufficient /nix/store/abc-gaze/lib/security/pam_gaze_grosshack.so"
            ),
            vec![PathBuf::from(
                "/nix/store/abc-gaze/lib/security/pam_gaze_grosshack.so"
            )]
        );

        assert!(
            pam_line_module_paths("auth sufficient pam_gaze.so").is_empty(),
            "a bare module name resolves through the search directories instead"
        );
        assert!(
            pam_line_module_paths("# auth sufficient /nix/store/abc/lib/security/pam_gaze.so")
                .is_empty(),
            "commented lines are not part of the stack"
        );
        assert!(
            pam_line_module_paths("auth sufficient /usr/lib64/security/pam_fprintd.so").is_empty()
        );
    }

    #[test]
    fn pam_reference_parser_ignores_comments_and_accepts_absolute_paths() {
        assert!(!pam_line_has_reference("# auth sufficient pam_gaze.so"));
        assert!(!pam_line_has_reference("auth include system-auth"));
        assert!(pam_line_has_reference("auth sufficient pam_gaze.so"));
        assert!(pam_line_has_reference(
            "auth sufficient /usr/lib/security/pam_gaze.so simultaneous"
        ));
        assert!(pam_line_has_reference(
            "auth sufficient /usr/lib/security/pam_gaze_grosshack.so debug"
        ));
        assert!(pam_line_has_reference(
            "auth sufficient /usr/lib/security/pam_gaze.so debug"
        ));
        assert!(!pam_line_has_reference(
            "auth sufficient pam_gaze.so.disabled"
        ));
    }

    #[test]
    fn pam_ordering_flags_modules_stacked_before_gaze() {
        let stacked_behind = "auth [success=3 default=ignore] pam_fprintd.so\n\
             auth [success=2 default=ignore] pam_unix.so\n\
             auth [success=1 default=ignore] pam_gaze.so\n";
        assert_eq!(
            find_pam_ordering_conflicts(stacked_behind),
            vec!["pam_unix.so", "pam_fprintd.so"]
        );

        let stacked_first = "auth sufficient pam_gaze.so\n\
             auth sufficient pam_unix.so try_first_pass nullok\n";
        assert!(find_pam_ordering_conflicts(stacked_first).is_empty());

        assert!(find_pam_ordering_conflicts("auth include system-auth\n").is_empty());
    }

    #[test]
    fn a_retry_entry_is_not_a_stalled_first_pass() {
        let retry_stack = "auth sufficient pam_gaze.so simultaneous\n\
             auth sufficient pam_unix.so try_first_pass nullok\n\
             auth sufficient pam_gaze.so retry\n";
        assert!(find_pam_ordering_conflicts(retry_stack).is_empty());
        assert!(!find_misplaced_retry_entry(retry_stack));
    }

    #[test]
    fn a_lone_retry_entry_below_the_password_is_not_flagged_as_stalled() {
        let lone_retry = "auth sufficient pam_unix.so try_first_pass nullok\n\
             auth sufficient pam_gaze.so retry\n";
        assert!(find_pam_ordering_conflicts(lone_retry).is_empty());
        assert!(!find_misplaced_retry_entry(lone_retry));
    }

    #[test]
    fn a_retry_entry_above_the_password_is_unreachable() {
        let misplaced = "auth sufficient pam_gaze.so retry\n\
             auth sufficient pam_unix.so try_first_pass nullok\n";
        assert!(find_misplaced_retry_entry(misplaced));
    }

    #[test]
    fn a_stack_without_a_retry_entry_reports_nothing() {
        assert!(!find_misplaced_retry_entry(
            "auth sufficient pam_gaze.so\nauth sufficient pam_unix.so\n"
        ));
    }

    #[test]
    fn a_fingerprint_module_does_not_count_as_the_password_module() {
        let fprintd_only = "auth sufficient pam_fprintd.so\n\
             auth sufficient pam_gaze.so retry\n\
             auth sufficient pam_unix.so try_first_pass nullok\n";
        assert!(find_misplaced_retry_entry(fprintd_only));
    }

    #[test]
    fn retry_is_only_a_mode_token_on_a_gaze_line() {
        assert!(pam_line_is_retry("auth sufficient pam_gaze.so retry"));
        assert!(!pam_line_is_retry("auth sufficient pam_gaze.so"));
        assert!(!pam_line_is_retry("auth sufficient pam_unix.so retry"));
    }

    #[test]
    fn deprecated_pam_line_detects_grosshack() {
        let has_grosshack = |line: &str| {
            let line = line.split('#').next().unwrap_or_default().trim();
            line.split_ascii_whitespace().any(|token| {
                token == "pam_gaze_grosshack.so" || token.ends_with("/pam_gaze_grosshack.so")
            })
        };

        assert!(has_grosshack("auth sufficient pam_gaze_grosshack.so"));
        assert!(has_grosshack(
            "auth sufficient /lib/security/pam_gaze_grosshack.so"
        ));
        assert!(!has_grosshack("# auth sufficient pam_gaze_grosshack.so"));
        assert!(!has_grosshack("auth sufficient pam_gaze.so simultaneous"));
    }
}
