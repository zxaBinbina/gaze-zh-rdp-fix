// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

pub(super) fn detected_source_remedy(
    cameras: &[(String, String)],
    key: &str,
    automatic: Option<&str>,
) -> String {
    let detected: Vec<&str> = cameras
        .iter()
        .filter(|(_, target)| target != gaze_core::config::DEFAULT_RGB_CAMERA)
        .map(|(_, target)| target.as_str())
        .collect();

    if detected.is_empty() {
        return match automatic {
            Some(automatic) => format!(
                "当前未提供 PipeWire 来源。重新连接摄像头，然后将 {key} 设为检测到的来源，或设为 \"{automatic}\" 以便在运行时解析。"
            ),
            None => {
                format!("当前未提供 PipeWire 来源。重新连接摄像头，然后将 {key} 设为检测到的来源。")
            }
        };
    }

    format!(
        "运行 `gaze config` 交互式选择，或将 {key} 设为检测到的来源之一：{}",
        detected
            .iter()
            .map(|target| format!("\"{target}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub(super) fn gstreamer_package_hint_for(os_release: &str) -> &'static str {
    let os_release = os_release.to_ascii_lowercase();
    if ["arch", "manjaro", "omarchy"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "使用 `sudo pacman -S gst-plugins-base gst-plugins-good gst-plugin-pipewire` 安装。"
    } else if ["debian", "ubuntu"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "使用 `sudo apt install gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-pipewire` 安装。"
    } else if ["fedora", "rhel", "centos"]
        .iter()
        .any(|family| os_release.contains(family))
    {
        "使用 `sudo dnf install gstreamer1-plugins-base gstreamer1-plugins-good pipewire-gstreamer` 安装。"
    } else if os_release.contains("suse") {
        "使用 `sudo zypper install gstreamer-plugins-base gstreamer-plugins-good gstreamer-plugin-pipewire` 安装。"
    } else {
        "安装此发行版的 GStreamer base、good 和 PipeWire 插件包。"
    }
}

pub(super) fn gstreamer_package_hint() -> &'static str {
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    gstreamer_package_hint_for(&os_release)
}

pub(super) fn check_gstreamer_plugins(report: &mut Report) -> bool {
    match gaze_vision::camera::missing_camera_elements() {
        Ok(missing) if missing.is_empty() => {
            report.pass(
                "GStreamer 插件",
                "base、JPEG/V4L2 和 PipeWire 摄像头组件可用",
            );
            true
        }
        Ok(missing) => {
            report.error(
                "GStreamer 插件",
                format!("缺少必需的摄像头组件：{}", missing.join(", ")),
                gstreamer_package_hint(),
            );
            false
        }
        Err(err) => {
            report.error(
                "GStreamer 插件",
                format!("无法初始化插件注册表：{err}"),
                gstreamer_package_hint(),
            );
            false
        }
    }
}

pub(super) fn check_cameras(report: &mut Report, config: Option<&Config>) {
    if !check_gstreamer_plugins(report) {
        return;
    }

    let Some(config) = config else {
        return;
    };

    let rgb = config.cameras.rgb.trim();
    if !rgb.is_empty() {
        match gaze_vision::camera::enumerate_cameras() {
            Ok(cameras) => {
                let detected = cameras
                    .iter()
                    .filter(|(_, target)| target != gaze_core::config::DEFAULT_RGB_CAMERA)
                    .count();
                if rgb == gaze_core::config::DEFAULT_RGB_CAMERA {
                    if detected > 0 {
                        report.pass(
                            "RGB 摄像头",
                            format!("通过 PipeWire 可见 {detected} 个彩色摄像头"),
                        );
                    } else {
                        report.warning(
                            "RGB 摄像头",
                            "PipeWire 未提供物理彩色摄像头",
                            "请检查摄像头隐私控制，并在本地桌面会话中运行 `gaze config`。",
                        );
                    }
                } else if rgb.starts_with("pipewiresrc target-object=") {
                    if cameras.iter().any(|(_, target)| target == rgb) {
                        report.pass("RGB 摄像头", "已配置的 PipeWire 来源可见");
                    } else {
                        report.error(
                            "RGB 摄像头",
                            format!("已配置的来源不可见：{rgb}"),
                            detected_source_remedy(
                                &cameras,
                                "cameras.rgb",
                                Some(gaze_core::config::DEFAULT_RGB_CAMERA),
                            ),
                        );
                    }
                } else if let Some((vid, pid)) = gaze_vision::camera::parse_usb_spec(rgb) {
                    report.pass(
                        "RGB 摄像头",
                        format!("在运行时解析 USB {vid:04x}:{pid:04x} 的彩色节点"),
                    );
                } else if rgb.starts_with("/dev/video") {
                    match fs::metadata(rgb) {
                        Ok(metadata) if metadata.file_type().is_char_device() => {
                            report.pass("RGB 摄像头", format!("{rgb} 是字符设备"));
                        }
                        Ok(_) => report.error(
                            "RGB 摄像头",
                            format!("{rgb} 不是字符设备"),
                            "将 cameras.rgb 指向 /dev/video* 节点。",
                        ),
                        Err(err) => report.error(
                            "RGB 摄像头",
                            format!("无法访问 {rgb}：{err}"),
                            "检查设备路径和权限。",
                        ),
                    }
                } else {
                    report.warning(
                        "RGB 摄像头",
                        "已配置自定义 GStreamer 来源，本次只读检查未打开该来源",
                        "运行 `gaze auth`，确认自定义来源能输出画面。",
                    );
                }
            }
            Err(err) => report.error(
                "RGB 摄像头",
                format!("GStreamer 摄像头枚举失败：{err}"),
                "请确认已安装 GStreamer PipeWire 插件且 PipeWire 正在运行。",
            ),
        }
    }

    let ir = config.cameras.ir.trim();
    if ir.is_empty() {
        return;
    }
    if ir.starts_with("/dev/video") {
        match fs::metadata(ir) {
            Ok(metadata) if metadata.file_type().is_char_device() => {
                report.pass("红外摄像头", format!("{ir} 是字符设备"));
            }
            Ok(_) => report.error(
                "红外摄像头",
                format!("{ir} 不是设备节点"),
                "请选择红外摄像头的 /dev/video* 节点。",
            ),
            Err(err) => report.error(
                "红外摄像头",
                format!("无法访问 {ir}：{err}"),
                "修正 cameras.ir 或重新连接红外摄像头。",
            ),
        }
    } else if ir.starts_with("pipewiresrc target-object=") {
        match gaze_vision::camera::enumerate_ir_cameras() {
            Ok(cameras) if cameras.iter().any(|(_, target)| target == ir) => {
                report.pass("红外摄像头", "已配置的 PipeWire 来源可见");
            }
            Ok(cameras) => report.error(
                "红外摄像头",
                format!("已配置的来源不可见：{ir}"),
                detected_source_remedy(&cameras, "cameras.ir", None),
            ),
            Err(err) => report.error(
                "红外摄像头",
                format!("GStreamer 红外摄像头枚举失败：{err}"),
                "请确认 PipeWire 正在运行且已连接红外设备。",
            ),
        }
    } else if let Some((vid, pid)) = gaze_vision::camera::parse_usb_spec(ir) {
        report.pass(
            "红外摄像头",
            format!("在运行时解析 USB {vid:04x}:{pid:04x} 的红外节点"),
        );
    } else {
        report.warning(
            "红外摄像头",
            "已配置自定义 GStreamer 来源，本次只读检查未打开该来源",
            "运行 `gaze auth`，确认红外来源能输出画面。",
        );
    }

    if config.cameras.emitter_enabled {
        check_i2c_emitter(report, ir);
    }
}

pub(super) fn check_i2c_emitter(report: &mut Report, ir: &str) {
    let Some(node) = gaze_vision::camera::resolve_node(ir) else {
        return;
    };
    match gaze_core::ir::i2c::I2cEmitter::diagnose(&node) {
        None => {}
        Some(Ok(emitter)) => report.pass(
            "红外发射器",
            format!("{} 匹配 {} 上的 {node}", emitter.name(), emitter.bus()),
        ),
        Some(Err(reason)) => report.warning(
            "红外发射器",
            format!("{node} 的 I2C 发射器配置不适用：{reason}"),
            "加载 i2c-dev 模块，确认红外桥接正在运行且已绑定传感器驱动。在此之前，认证将继续在无照明状态下进行。",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gstreamer_plugin_remedies_use_distro_package_names() {
        for (os_release, packages) in [
            (
                "ID=omarchy\nID_LIKE=arch\n",
                [
                    "gst-plugins-base",
                    "gst-plugins-good",
                    "gst-plugin-pipewire",
                ],
            ),
            (
                "ID=ubuntu\nID_LIKE=debian\n",
                [
                    "gstreamer1.0-plugins-base",
                    "gstreamer1.0-plugins-good",
                    "gstreamer1.0-pipewire",
                ],
            ),
            (
                "ID=fedora\n",
                [
                    "gstreamer1-plugins-base",
                    "gstreamer1-plugins-good",
                    "pipewire-gstreamer",
                ],
            ),
            (
                "ID=opensuse-tumbleweed\nID_LIKE=suse\n",
                [
                    "gstreamer-plugins-base",
                    "gstreamer-plugins-good",
                    "gstreamer-plugin-pipewire",
                ],
            ),
        ] {
            let hint = gstreamer_package_hint_for(os_release);
            for package in packages {
                assert!(hint.contains(package), "{hint:?} does not name {package}");
            }
        }
    }

    #[test]
    fn camera_remedy_lists_detected_sources() {
        let cameras = vec![
            (
                "主摄像头".to_string(),
                gaze_core::config::DEFAULT_RGB_CAMERA.to_string(),
            ),
            (
                "Integrated Camera".to_string(),
                "pipewiresrc target-object=v4l2_input.pci-0000_00_14_0".to_string(),
            ),
        ];

        let remedy = detected_source_remedy(
            &cameras,
            "cameras.rgb",
            Some(gaze_core::config::DEFAULT_RGB_CAMERA),
        );
        assert!(remedy.contains("cameras.rgb"), "{remedy}");
        assert!(
            remedy.contains("\"pipewiresrc target-object=v4l2_input.pci-0000_00_14_0\""),
            "the detected source must be quoted verbatim for copy-paste: {remedy}"
        );
        assert!(
            !remedy.contains("\"primary\""),
            "the primary pseudo-source is not a selectable node: {remedy}"
        );
    }

    #[test]
    fn camera_remedy_only_offers_primary_where_it_is_valid() {
        let none_detected = vec![(
            "主摄像头".to_string(),
            gaze_core::config::DEFAULT_RGB_CAMERA.to_string(),
        )];

        let rgb = detected_source_remedy(
            &none_detected,
            "cameras.rgb",
            Some(gaze_core::config::DEFAULT_RGB_CAMERA),
        );
        assert!(rgb.contains("cameras.rgb"), "{rgb}");
        assert!(rgb.contains("\"primary\""), "{rgb}");

        let ir = detected_source_remedy(&[], "cameras.ir", None);
        assert!(ir.contains("cameras.ir"), "{ir}");
        assert!(
            !ir.contains("primary"),
            "cameras.ir has no primary fallback: {ir}"
        );
    }
}
