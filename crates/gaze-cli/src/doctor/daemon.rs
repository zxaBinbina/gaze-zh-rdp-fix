// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DaemonCredentials {
    pub(super) uid: u32,
    pub(super) gids: Vec<u32>,
    pub(super) dac_override: bool,
}

pub(super) fn daemon_credentials() -> Option<DaemonCredentials> {
    let (ok, text) = command_output(
        "systemctl",
        &[
            "show",
            "gazed",
            "-p",
            "LoadState",
            "-p",
            "User",
            "-p",
            "SupplementaryGroups",
            "-p",
            "CapabilityBoundingSet",
        ],
    )
    .ok()?;
    if !ok {
        return None;
    }
    parse_daemon_credentials(&text)
}

pub(super) fn parse_daemon_credentials(text: &str) -> Option<DaemonCredentials> {
    let mut load_state = "";
    let mut user = "";
    let mut groups = "";
    let mut capabilities = "";
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "LoadState" => load_state = value.trim(),
            "User" => user = value.trim(),
            "SupplementaryGroups" => groups = value.trim(),
            "CapabilityBoundingSet" => capabilities = value.trim(),
            _ => {}
        }
    }

    if load_state != "loaded" {
        return None;
    }
    if !(user.is_empty() || user == "root" || user == "0") {
        return None;
    }

    let mut gids = vec![0];
    gids.extend(groups.split_whitespace().filter_map(group_gid));
    Some(DaemonCredentials {
        uid: 0,
        gids,
        dac_override: capabilities
            .split_whitespace()
            .any(|capability| capability.eq_ignore_ascii_case("cap_dac_override")),
    })
}

pub(super) fn node_openable(
    uid: u32,
    gid: u32,
    mode: u32,
    credentials: &DaemonCredentials,
) -> bool {
    if credentials.dac_override {
        return true;
    }
    let class = if uid == credentials.uid {
        0o600
    } else if credentials.gids.contains(&gid) {
        0o060
    } else {
        0o006
    };
    mode & class == class
}

pub(super) fn group_gid(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    Some(unsafe { (*entry).gr_gid })
}

pub(super) fn user_uid(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    Some(unsafe { (*entry).pw_uid })
}

pub(super) fn user_name(uid: u32) -> String {
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return uid.to_string();
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).pw_name) };
    name.to_str().map(str::to_owned).unwrap_or(uid.to_string())
}

pub(super) fn group_name(gid: u32) -> String {
    let entry = unsafe { libc::getgrgid(gid) };
    if entry.is_null() {
        return gid.to_string();
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*entry).gr_name) };
    name.to_str().map(str::to_owned).unwrap_or(gid.to_string())
}

pub(super) async fn read_daemon_config(
    proxy: &GazeProxy<'_>,
    ready_wait: Duration,
) -> zbus::Result<Config> {
    let deadline = Instant::now() + ready_wait;
    loop {
        match proxy.config().await {
            Ok(config) => return Ok(config.into()),
            Err(err) if dbus_is_not_activatable(&err) && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Whether `gazed` currently owns its well-known name, retrying for `ready_wait` so a
/// daemon still downloading models is not mistaken for one that will never appear.
/// Connecting to the system bus succeeds regardless, so only this distinguishes the two.
pub(super) async fn gaze_name_has_owner(proxy: &GazeProxy<'_>, ready_wait: Duration) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(proxy.inner().connection()).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(GAZE_BUS_NAME) else {
        return false;
    };
    let deadline = Instant::now() + ready_wait;
    loop {
        if let Ok(true) = dbus.name_has_owner(name.clone()).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) struct Daemon {
    pub(super) proxy: GazeProxy<'static>,
    pub(super) config: Option<Config>,
}

pub(super) async fn connect_daemon(report: &mut Report) -> Option<Daemon> {
    let service_state = match command_output("systemctl", &["is-active", "gazed"]) {
        Ok((_, state)) => state,
        Err(_) => String::new(),
    };
    let daemon_starting = service_state == "active";
    let ready_wait = if daemon_starting {
        DAEMON_READY_TIMEOUT
    } else {
        Duration::ZERO
    };

    let proxy = match tokio::time::timeout(DAEMON_TIMEOUT, gaze_core::dbus::connect_gaze()).await {
        Ok(Ok(proxy)) => proxy,
        Ok(Err(err)) => {
            report.error(
                "DBus",
                format!("无法连接系统总线：{err}"),
                "运行 `systemctl status dbus`，并确认系统总线套接字存在。",
            );
            return None;
        }
        Err(_) => {
            report.error(
                "DBus",
                "连接系统总线超时",
                "运行 `systemctl status dbus`，并确认系统总线套接字存在。",
            );
            return None;
        }
    };

    let name_wait_started = Instant::now();
    let name_owned = gaze_name_has_owner(&proxy, ready_wait).await;
    // `gazed` downloads models before claiming its name. Once it is on the bus,
    // the remaining budget is enough for the config call; do not apply it twice.
    let ready_wait = ready_wait.saturating_sub(name_wait_started.elapsed());

    if name_owned {
        report.pass("DBus", "gazed 在系统总线上持有 com.gundulabs.Gaze");
    } else {
        // Later calls would fail with the same "not activatable" error. Report the cause
        // once rather than repeating it as separate camera and enrollment faults.
        let (message, fix) = if !gaze_core::cpu::supports_inference() {
            (
                "gazed 无法在此 CPU 上运行（缺少 AVX2），因此无法连接系统总线".to_string(),
                gaze_core::cpu::UNSUPPORTED_CPU_FIX.to_string(),
            )
        } else if daemon_starting {
            (
                "gazed 正在运行，但尚未取得 com.gundulabs.Gaze（可能正在下载模型）".to_string(),
                "等待首次运行的模型下载完成，然后重新运行 `gaze doctor`。".to_string(),
            )
        } else {
            (
                format!(
                    "gazed 不在系统总线上（服务状态：{}）",
                    if service_state.is_empty() {
                        "未报告状态"
                    } else {
                        service_state.as_str()
                    }
                ),
                "运行 `sudo systemctl start gazed`；如果服务未持续运行，请查看 `journalctl -u gazed -n 100 --no-pager`。"
                    .to_string(),
            )
        };
        report.error("DBus", message, fix);
        return None;
    }

    let config = match tokio::time::timeout(
        ready_wait + DAEMON_TIMEOUT,
        read_daemon_config(&proxy, ready_wait),
    )
    .await
    {
        Ok(Ok(config)) => {
            report.pass("守护进程", "gazed 已响应配置请求");
            Some(config)
        }
        // The name was owned a moment ago, so losing it here means gazed exited mid-check.
        Ok(Err(err)) if dbus_is_not_activatable(&err) => {
            report.error(
                "守护进程",
                "doctor 查询时，gazed 已退出系统总线",
                "运行 `journalctl -u gazed -n 100 --no-pager` 查看退出原因。",
            );
            None
        }
        Ok(Err(err)) => {
            report.error(
                "守护进程",
                format!("gazed 未返回配置：{}", dbus_error_message(&err)),
                "重启 gazed 并查看日志。",
            );
            None
        }
        Err(_) => {
            report.error("守护进程", "读取 gazed 配置超时", "重启 gazed 并查看日志。");
            None
        }
    };
    Some(Daemon { proxy, config })
}

pub(super) async fn check_daemon(
    report: &mut Report,
    username: &str,
    proxy: Option<&GazeProxy<'static>>,
    config: Option<&Config>,
    benchmark: bool,
) {
    let Some(proxy) = proxy else {
        check_cameras(report, config);
        return;
    };

    match tokio::time::timeout(DAEMON_TIMEOUT, proxy.is_camera_available()).await {
        Ok(Ok(true)) => report.pass("摄像头会话", "守护进程可以访问当前 PipeWire 会话"),
        Ok(Ok(false)) => report.error(
            "摄像头会话",
            "守护进程找不到此会话可用的 PipeWire 运行环境",
            "在本地图形会话中运行此命令，并确认 /run/user/$UID/pipewire-0 存在。",
        ),
        Ok(Err(err)) => report.error(
            "摄像头会话",
            format!("可用性检查失败：{}", dbus_error_message(&err)),
            "查看 gazed 日志中的 PipeWire 或登录会话错误。",
        ),
        Err(_) => report.error("摄像头会话", "可用性检查超时", "重启 gazed 并查看日志。"),
    }
    check_cameras(report, config);

    match tokio::time::timeout(DAEMON_TIMEOUT, proxy.list_faces(username)).await {
        Ok(Ok(faces)) if faces.is_empty() => report.warning(
            "录入",
            format!("尚未为 {username} 录入人脸"),
            "运行 `gaze add-face default`。",
        ),
        Ok(Ok(faces)) => {
            report.pass(
                "录入",
                format!("已为 {username} 录入 {} 个人脸档案", faces.len()),
            );
            if let Some(config) = config {
                let missing_rgb = !config.cameras.rgb.trim().is_empty()
                    && faces.iter().any(|(_, _, has_rgb, _)| !has_rgb);
                let missing_ir = !config.cameras.ir.trim().is_empty()
                    && faces.iter().any(|(_, _, _, has_ir)| !has_ir);
                if missing_rgb || missing_ir {
                    let spectra = match (missing_rgb, missing_ir) {
                        (true, true) => "RGB 和红外",
                        (true, false) => "RGB",
                        (false, true) => "红外",
                        (false, false) => unreachable!(),
                    };
                    report.warning(
                        "录入覆盖范围",
                        format!("一个或多个人脸档案缺少 {spectra} 采集数据"),
                        "对缺少已配置摄像头光谱数据的人脸档案运行 `gaze refine-face <name>`。",
                    );
                } else {
                    report.pass("录入覆盖范围", "所有人脸档案均覆盖已配置摄像头的光谱");
                }
            }
        }
        Ok(Err(err)) if dbus_is_file_not_found(&err) => report.warning(
            "录入",
            format!("尚未为 {username} 录入人脸"),
            "运行 `gaze add-face default`。",
        ),
        Ok(Err(err)) => report.error(
            "录入",
            format!("无法列出 {username} 的人脸：{}", dbus_error_message(&err)),
            "运行 `gaze list-faces` 并查看守护进程日志。",
        ),
        Err(_) => report.error(
            "录入",
            format!("检查 {username} 的人脸时超时"),
            "重启 gazed 并查看日志。",
        ),
    }

    if benchmark {
        check_benchmark(report, proxy).await;
    }
}

pub(super) async fn check_benchmark(report: &mut Report, proxy: &GazeProxy<'_>) {
    let term = Term::stdout();
    let _ = term.write_line(&format!(
        "{} 正在测试模型推理性能（可能需要几秒钟）...",
        style("i").cyan().bold()
    ));

    let outcome = tokio::time::timeout(BENCHMARK_TIMEOUT, try_benchmark_from_daemon(proxy)).await;
    let _ = term.clear_last_lines(1);

    match outcome {
        Ok(Ok(Some(results))) => {
            for result in results {
                let timings = format!(
                    "{} [{} / {}]：平均 {:.1}毫秒（{:.1} 帧/秒），p95 {:.1}毫秒，最短 {:.1}毫秒",
                    result.component,
                    result.execution_provider,
                    result.device,
                    result.mean_ms,
                    result.fps,
                    result.p95_ms,
                    result.min_ms
                );
                if result.ran_as_configured() {
                    report.pass("性能测试", timings);
                } else {
                    report.warning(
                        "性能测试",
                        format!(
                            "{timings}；未使用已配置的 {}/{}：{}",
                            result.requested_execution_provider,
                            result.requested_device,
                            if result.fallback_reason.is_empty() {
                                "未报告原因"
                            } else {
                                result.fallback_reason.as_str()
                            }
                        ),
                        "检查 /usr/lib/gaze/runtimes 中的厂商运行时，重启 gazed 并查看日志；cpu/cpu 会禁用加速。",
                    );
                }
            }
        }
        Ok(Ok(None)) => report.warning(
            "性能测试",
            "正在运行的守护进程报告的性能测试数据格式无法被此版本读取",
            "使用 `systemctl restart gazed` 重启。",
        ),
        Ok(Err(err)) => report.warning(
            "性能测试",
            format!("gazed 无法运行性能测试：{err}"),
            "重启 gazed 并查看日志。",
        ),
        Err(_) => report.warning("性能测试", "性能测试超时", "重启 gazed 并查看日志。"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(gids: &[u32], dac_override: bool) -> DaemonCredentials {
        DaemonCredentials {
            uid: 0,
            gids: gids.to_vec(),
            dac_override,
        }
    }

    #[test]
    fn root_owned_tpm_node_is_openable_without_dac_override() {
        let creds = credentials(&[0], false);
        assert!(node_openable(0, 972, 0o660, &creds));
        assert!(!node_openable(0, 972, 0o060, &creds));
    }

    #[test]
    fn tss_owned_tpm_node_needs_the_group_or_the_capability() {
        let tss_uid = 972;
        let tss_gid = 972;

        let bare_root = credentials(&[0], false);
        assert!(
            !node_openable(tss_uid, tss_gid, 0o660, &bare_root),
            "the reporter's Ubuntu node must read as unopenable"
        );

        assert!(node_openable(
            tss_uid,
            tss_gid,
            0o660,
            &credentials(&[0, tss_gid], false)
        ));
        assert!(node_openable(
            tss_uid,
            tss_gid,
            0o660,
            &credentials(&[0], true)
        ));
        assert!(node_openable(tss_uid, tss_gid, 0o666, &bare_root));
    }

    #[test]
    fn group_access_does_not_rescue_an_owner_class_mismatch() {
        let creds = credentials(&[0, 972], false);
        assert!(!node_openable(0, 972, 0o060, &creds));
    }

    #[test]
    fn daemon_credentials_come_from_the_effective_unit() {
        let parsed = parse_daemon_credentials(
            "LoadState=loaded\nCapabilityBoundingSet=cap_dac_read_search cap_dac_override\nUser=\nSupplementaryGroups=video",
        )
        .expect("a loaded root unit must be understood");
        assert_eq!(parsed.uid, 0);
        assert!(parsed.dac_override);
        assert!(parsed.gids.contains(&0));

        let capless = parse_daemon_credentials(
            "LoadState=loaded\nCapabilityBoundingSet=cap_dac_read_search\nUser=\nSupplementaryGroups=video",
        )
        .expect("a loaded root unit must be understood");
        assert!(!capless.dac_override);

        assert_eq!(
            parse_daemon_credentials("LoadState=not-found\nUser=\nCapabilityBoundingSet="),
            None,
            "an uninstalled unit must not be judged"
        );
        assert_eq!(
            parse_daemon_credentials(
                "LoadState=loaded\nUser=gaze\nCapabilityBoundingSet=cap_dac_read_search"
            ),
            None,
            "a custom User= must not be judged"
        );
    }
}
