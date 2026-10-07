// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

pub(super) fn check_systemd(report: &mut Report) {
    if !Path::new("/run/systemd/system").exists() {
        report.warning(
            "systemd",
            "systemd 未运行，无法检查 gazed 服务状态",
            "在常规安装环境中，使用 systemd 启动并运行 `systemctl status gazed`。",
        );
        return;
    }

    match command_output("systemctl", &["is-active", "gazed"]) {
        Ok((true, state)) if state == "active" => report.pass("服务", "gazed 正在运行"),
        Ok((_, state)) => report.error(
            "服务",
            format!("gazed 的状态为 {state}"),
            "运行 `sudo systemctl enable --now gazed`；如失败，请查看 `journalctl -u gazed -n 100 --no-pager`。",
        ),
        Err(err) => report.error(
            "服务",
            format!("无法查询 gazed：{err}"),
            "运行 `systemctl status gazed`。",
        ),
    }

    match command_output("systemctl", &["is-enabled", "gazed"]) {
        Ok((true, state)) if state == "enabled" => {
            report.pass("自动启动", "gazed 已启用开机启动");
        }
        Ok((_, state)) => report.warning(
            "自动启动",
            format!("gazed 的状态为 {state}"),
            "运行 `sudo systemctl enable gazed`，使重启后仍可使用认证。",
        ),
        Err(err) => report.warning(
            "自动启动",
            format!("无法查询 gazed 的启用状态：{err}"),
            "运行 `systemctl is-enabled gazed`。",
        ),
    }
}

pub(super) fn check_config(report: &mut Report) -> Option<Config> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        report.error(
            "配置",
            format!("{CONFIG_PATH} 不存在"),
            "重新安装 Gaze 或恢复软件包提供的配置文件。",
        );
        return None;
    }

    check_config_permissions(report, path);

    let config = match Config::load_from(CONFIG_PATH) {
        Ok(config) => {
            let unknown = fs::read_to_string(CONFIG_PATH)
                .map(|contents| unknown_config_keys(&contents))
                .unwrap_or_default();
            if unknown.is_empty() {
                report.pass("配置", format!("{CONFIG_PATH} 解析成功"));
            } else {
                report.warning(
                    "配置",
                    format!(
                        "{CONFIG_PATH} 可以解析，但 Gaze 不读取以下配置项：{}",
                        unknown.join(", ")
                    ),
                    "删除或修正这些键；它们不会生效，因此拼写错误的设置会被忽略。",
                );
            }
            config
        }
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|err| err.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            report.pass(
                "配置",
                format!(
                    "此处无法读取 {CONFIG_PATH}；已通过 gazed 检查配置值，但未检查文件中的未知键"
                ),
            );
            return None;
        }
        Err(err) => {
            report.error(
                "配置",
                format!("无法加载 {CONFIG_PATH}：{err}"),
                "检查文件并修正 TOML 语法，然后运行 `sudo systemctl restart gazed`。",
            );
            return None;
        }
    };

    for check in config_findings(&config) {
        report.checks.push(check);
    }

    Some(config)
}

pub(super) fn check_config_permissions(report: &mut Report, path: &Path) {
    match fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.mode() & 0o777;
            if metadata.uid() != 0 {
                report.error(
                    "配置所有权",
                    format!("{CONFIG_PATH} 的所有者 UID 为 {}", metadata.uid()),
                    format!("运行 `sudo chown root:root {CONFIG_PATH}`。"),
                );
            } else if mode & 0o022 != 0 {
                report.error(
                    "配置权限",
                    format!("{CONFIG_PATH} 的权限模式 {mode:o} 允许写入"),
                    format!("运行 `sudo chmod 0644 {CONFIG_PATH}`。"),
                );
            } else {
                report.pass(
                    "配置权限",
                    format!("由 root 所有，且组和其他用户不可写（{mode:o}）"),
                );
            }
        }
        Err(err) => report.error(
            "配置权限",
            format!("无法检查 {CONFIG_PATH}：{err}"),
            format!("运行 `sudo stat {CONFIG_PATH}`。"),
        ),
    }
}

pub(super) fn config_findings(config: &Config) -> Vec<Check> {
    let mut findings = Vec::new();
    let mut error = |message: String, fix: &'static str| {
        findings.push(Check {
            level: Level::Error,
            name: "配置值",
            message,
            fix: Some(fix.to_string()),
        });
    };

    for err in config.security.validation_errors() {
        let fix = match err.field {
            SecurityField::Level | SecurityField::ModelQuality => {
                "使用 `gaze config` 选择受支持的安全级别。"
            }
            SecurityField::Threshold => {
                "在 /etc/gaze/config.toml 中设置有效的自定义 RGB 和红外阈值。"
            }
            SecurityField::HybridPolicy => "使用 default、or、fallback_on_dark 或 and。",
        };
        error(err.message, fix);
    }
    if let Err(err) = config.enrollment.validate() {
        error(
            err.to_string(),
            "将 enrollment.min_face_size_ratio 设为 0.10 至 0.75 之间的值。",
        );
    }
    if let Err(err) = config.cameras.validate() {
        error(
            err.to_string(),
            "将 cameras.parallel_capture 设为 never、auto 或 always。",
        );
    }
    if let Err(err) = config.inference.validate() {
        let fix = "在 [inference] 中使用 cpu/cpu、auto/npu、openvino/cpu、openvino/gpu、openvino/npu 或 vitis/npu。";
        error(err.to_string(), fix);
    }

    let rgb = config.cameras.rgb.trim();
    let ir = config.cameras.ir.trim();
    if rgb.is_empty() && ir.is_empty() {
        error(
            "cameras.rgb 和 cameras.ir 均为空".to_string(),
            "将 cameras.rgb 设为 \"primary\"，或配置红外摄像头。",
        );
    }
    if let Some(index) = rgb.strip_prefix("/dev/video") {
        if index.is_empty() || !index.chars().all(|c| c.is_ascii_digit()) {
            error(
                format!("RGB 摄像头节点 {rgb:?} 无效"),
                "使用 /dev/video<number>、usb:VVVV:PPPP、\"primary\" 或 GStreamer 来源。",
            );
        }
    } else if rgb.starts_with("usb:") && gaze_vision::camera::parse_usb_spec(rgb).is_none() {
        error(
            format!("RGB USB 规格 {rgb:?} 无效"),
            "使用十六进制 VID:PID 格式 usb:VVVV:PPPP，例如 usb:046d:085e。",
        );
    }

    if config.liveness.enabled {
        if !config.liveness.threshold.is_finite()
            || !(MIN_LIVENESS_THRESHOLD..=MAX_LIVENESS_THRESHOLD)
                .contains(&config.liveness.threshold)
        {
            error(
                format!(
                    "liveness.threshold 必须介于 {MIN_LIVENESS_THRESHOLD} 和 {MAX_LIVENESS_THRESHOLD} 之间，当前为 {}",
                    config.liveness.threshold
                ),
                "将 liveness.threshold 设为 0.10 至 1.0 之间的值。",
            );
        }
        if !config.liveness.max_seconds.is_finite()
            || !(MIN_LIVENESS_MAX_SECONDS..=MAX_LIVENESS_MAX_SECONDS)
                .contains(&config.liveness.max_seconds)
        {
            error(
                format!(
                    "liveness.max_seconds 必须介于 {MIN_LIVENESS_MAX_SECONDS} 和 {MAX_LIVENESS_MAX_SECONDS} 之间，当前为 {}",
                    config.liveness.max_seconds
                ),
                "将 liveness.max_seconds 设为 0.2 至 30.0 之间的值（默认为 2.0）。",
            );
        }
    }

    if findings.is_empty() {
        findings.push(Check {
            level: Level::Pass,
            name: "配置值",
            message: "摄像头、安全、录入、推理和活体检测的配置值有效".to_string(),
            fix: None,
        });
    }

    if config.cameras.emitter_enabled && ir.is_empty() {
        findings.push(Check {
            level: Level::Warning,
            name: "红外发射器",
            message: "cameras.emitter_enabled 为 true，但 cameras.ir 为空".to_string(),
            fix: Some("配置 cameras.ir 或禁用 emitter_enabled。".to_string()),
        });
    }
    if config.cameras.parallel_capture() == "always" && !ir.is_empty() {
        findings.push(Check {
            level: Level::Warning,
            name: "并行采集",
            message: "cameras.parallel_capture 为 \"always\"，将同时输出 RGB 和红外画面，而不检查摄像头是否支持"
                .to_string(),
            fix: Some(
                "如果混合认证开始报错“红外摄像头数据流意外停止”，请使用 \"auto\" 或 \"never\"。"
                    .to_string(),
            ),
        });
    }
    if !config.liveness.enabled {
        findings.push(Check {
            level: Level::Warning,
            name: "活体检测",
            message: "防伪检测已禁用".to_string(),
            fix: Some("请启用 [liveness]，除非您有意接受照片或屏幕欺骗的风险。".to_string()),
        });
    }
    if config.enrollment.max_templates == 0 {
        findings.push(Check {
            level: Level::Warning,
            name: "录入数量限制",
            message: "max_templates 为零，已禁用模板淘汰".to_string(),
            fix: Some("将 enrollment.max_templates 设为正数（默认为 2）。".into()),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_default_config_has_no_errors() {
        let findings = config_findings(&Config::default());
        assert!(!findings.iter().any(|check| check.level == Level::Error));
    }

    #[test]
    fn config_checks_invalid_thresholds_and_camera_sources() {
        let mut config = Config::default();
        config.security.level = "custom".to_string();
        config.security.detector = "standard".to_string();
        config.security.recognizer = "standard".to_string();
        config.security.rgb_threshold = 1.5;
        config.security.ir_threshold = -0.1;
        config.security.hybrid_policy = "sometimes".to_string();
        config.cameras.rgb = "/dev/videoX".to_string();
        config.enrollment.min_face_size_ratio = 0.05;
        config.liveness.threshold = f64::NAN;
        config.liveness.max_seconds = 0.0;

        let findings = config_findings(&config);
        let messages = findings
            .iter()
            .map(|check| check.message.as_str())
            .collect::<Vec<_>>();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("security.rgb_threshold"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("security.ir_threshold"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("hybrid_policy"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("RGB 摄像头节点"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("enrollment.min_face_size_ratio"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("liveness.threshold"))
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("max_seconds"))
        );
    }

    #[test]
    fn config_checks_the_parallel_capture_mode() {
        let mut config = Config::default();
        config.cameras.parallel_capture = "sometimes".to_string();
        assert!(
            config_findings(&config)
                .iter()
                .any(|check| check.level == Level::Error
                    && check.message.contains("cameras.parallel_capture"))
        );

        let mut forced = Config::default();
        forced.cameras.ir = "/dev/video2".to_string();
        forced.cameras.parallel_capture = "always".to_string();
        assert!(config_findings(&forced).iter().any(
            |check| check.level == Level::Warning && check.message.contains("parallel_capture")
        ));

        let mut detected = Config::default();
        detected.cameras.ir = "/dev/video2".to_string();
        detected.cameras.parallel_capture = "auto".to_string();
        assert!(
            !config_findings(&detected)
                .iter()
                .any(|check| check.message.contains("parallel_capture"))
        );
    }

    #[test]
    fn every_invalid_security_field_is_reported_exactly_once() {
        let mut config = Config::default();
        config.security.level = "custom".to_string();
        config.security.detector = "standard".to_string();
        config.security.recognizer = "standard".to_string();
        config.security.rgb_threshold = 1.5;
        config.security.ir_threshold = -0.1;
        config.security.hybrid_policy = "sometimes".to_string();

        let findings = config_findings(&config);
        let count = |needle: &str| {
            findings
                .iter()
                .filter(|check| check.message.contains(needle))
                .count()
        };
        assert_eq!(count("security.rgb_threshold"), 1);
        assert_eq!(count("security.ir_threshold"), 1);
        assert_eq!(count("security.hybrid_policy"), 1);
    }

    #[test]
    fn invalid_security_fields_get_their_own_fix() {
        let mut config = Config::default();
        config.security.level = "custom".to_string();
        config.security.detector = "standard".to_string();
        config.security.recognizer = "standard".to_string();
        config.security.rgb_threshold = 1.5;
        config.security.hybrid_policy = "sometimes".to_string();

        let fix_for = |needle: &str| {
            config_findings(&config)
                .into_iter()
                .find(|check| check.message.contains(needle))
                .and_then(|check| check.fix)
                .unwrap_or_default()
        };
        assert!(fix_for("security.rgb_threshold").contains("自定义 RGB 和红外阈值"));
        assert!(fix_for("security.hybrid_policy").contains("fallback_on_dark"));
    }
}
