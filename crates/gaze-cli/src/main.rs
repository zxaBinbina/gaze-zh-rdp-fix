// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

mod doctor;
mod keyring;
mod polkit;
mod selinux;
mod tui;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::CompleteEnv;
use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use console::{Term, style};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use futures::StreamExt;
use gaze_core::config::{
    AuthConfig, Config, DEFAULT_SECURITY_THRESHOLD, HYBRID_POLICY_LABELS,
    MAX_ENROLLMENT_FACE_SIZE_RATIO, MAX_LIVENESS_MAX_SECONDS, MAX_LIVENESS_THRESHOLD,
    MAX_SECURITY_THRESHOLD, MIN_ENROLLMENT_FACE_SIZE_RATIO, MIN_LIVENESS_MAX_SECONDS,
    MIN_LIVENESS_THRESHOLD, MIN_SECURITY_THRESHOLD, MODEL_QUALITY_LABELS, SECURITY_LEVEL_LABELS,
    START_DELAY_SCOPE_LABELS, SecurityLevel,
};
use gaze_core::dbus::{
    CaptureStatus, EnrollPrompt, GazeProxy, VerifyResult, apply_config_to_daemon,
    apply_config_with_keyring_to_daemon, connect_gaze, dbus_error_message, dbus_is_file_not_found,
    load_config_with_keyring_from_daemon, try_load_config_from_daemon,
};
use std::{future::Future, time::Duration};
use tui::{AuthScreen, BusyScreen, EnrollScreen, Tone, TuiAction, TuiTerminal};

fn is_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

fn resolve_current_user(sudo_user: Option<String>, user: Option<String>) -> String {
    [sudo_user, user]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| "root".into())
}

fn get_current_user() -> String {
    let sudo_user = is_root().then(|| std::env::var("SUDO_USER").ok()).flatten();
    resolve_current_user(sudo_user, std::env::var("USER").ok())
}

fn face_completer(current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return Vec::new();
    };
    rt.block_on(async {
        let Ok(proxy) = connect_gaze().await else {
            return Vec::new();
        };
        let Ok(faces) = proxy.list_faces(&get_current_user()).await else {
            return Vec::new();
        };
        faces
            .into_iter()
            .filter(|(face, ..)| face.starts_with(current))
            .map(|(face, ..)| CompletionCandidate::new(face))
            .collect()
    })
}

fn command_requires_root(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::AddFace { .. } => Some("add-face"),
        Commands::RefineFace { .. } => Some("refine-face"),
        Commands::RemoveFace { .. } => Some("remove-face"),
        Commands::RenameFace { .. } => Some("rename-face"),
        Commands::ClearUser { .. } => Some("clear-user"),
        Commands::Config { show } => (!show).then_some("config"),
        Commands::Keyring { .. } => Some("keyring"),
        Commands::Auth { .. }
        | Commands::ListFaces { .. }
        | Commands::Duress { .. }
        | Commands::Doctor { .. }
        | Commands::Uninstall { .. } => None,
    }
}

fn command_target_user(command: &Commands) -> Option<&str> {
    match command {
        Commands::Auth { user, .. }
        | Commands::ListFaces { user }
        | Commands::Duress { user, .. }
        | Commands::Doctor { user, .. } => user.as_deref(),
        _ => None,
    }
}

fn command_may_be_challenged(command: &Commands) -> bool {
    command_may_be_challenged_as(command, is_root(), &get_current_user())
}

fn command_may_be_challenged_as(command: &Commands, root: bool, current_user: &str) -> bool {
    !root
        && (matches!(command, Commands::Duress { clear: true, .. })
            || matches!(command_target_user(command), Some(user) if user != current_user))
}

const ESCALATION_MARKER: &str = "GAZE_ESCALATED";
const ESCALATION_PRESERVED_ENV: [&str; 1] = ["XDG_RUNTIME_DIR"];

fn reexec_as_root(name: &str) -> anyhow::Result<()> {
    if std::env::var_os(ESCALATION_MARKER).is_some() {
        anyhow::bail!("gaze {name} 已重新运行，但未获得 root 权限");
    }
    if !which("sudo") {
        anyhow::bail!("gaze {name} 需要 root 权限，但未找到 sudo");
    }

    let mut cmd = std::process::Command::new("sudo");
    cmd.arg("--")
        .arg("env")
        .arg(format!("{ESCALATION_MARKER}=1"));
    for key in ESCALATION_PRESERVED_ENV {
        if let Some(value) = std::env::var_os(key) {
            let mut pair = std::ffi::OsString::from(key);
            pair.push("=");
            pair.push(value);
            cmd.arg(pair);
        }
    }
    cmd.arg(std::env::current_exe()?)
        .args(std::env::args_os().skip(1));

    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn capture_tone(status: CaptureStatus) -> Tone {
    match status {
        CaptureStatus::Ready | CaptureStatus::Usable => Tone::Good,
        CaptureStatus::Unused | CaptureStatus::NoFace => Tone::Error,
        CaptureStatus::TooDark
        | CaptureStatus::Clipped
        | CaptureStatus::NotCentered
        | CaptureStatus::TooFar
        | CaptureStatus::TooClose => Tone::Warn,
    }
}

fn interactive_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
}

async fn run_busy<F, T>(title: &str, message: String, tone: Tone, future: F) -> anyhow::Result<T>
where
    F: Future<Output = T>,
{
    if !interactive_terminal() {
        return Ok(future.await);
    }

    let mut terminal = TuiTerminal::new()?;
    let mut tick = 0_u64;
    tokio::pin!(future);

    loop {
        terminal.draw_busy(&BusyScreen {
            title,
            message: &message,
            tone,
            tick,
        })?;
        if let Some(TuiAction::Cancel) = tui::poll_action()? {
            drop(terminal);
            anyhow::bail!("已取消");
        }

        tokio::select! {
            result = &mut future => {
                drop(terminal);
                return Ok(result);
            }
            _ = tokio::time::sleep(Duration::from_millis(80)) => {
                tick = tick.wrapping_add(1);
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "gaze", version, about = "Gaze 命令行界面")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 使用人脸识别认证用户
    Auth {
        #[arg(short, long)]
        user: Option<String>,
        #[arg(short, long, conflicts_with = "silent", help = "显示详细的认证指标")]
        verbose: bool,
        #[arg(short, long, help = "隐藏终端界面和所有输出；通过退出码报告结果")]
        silent: bool,
    },
    /// 按照引导从多个角度采集并录入人脸档案
    AddFace {
        #[arg(short, long)]
        user: Option<String>,
        #[arg(help = "要录入的人脸名称")]
        face: String,
    },
    /// 增加采集数据，改善现有人脸档案的识别效果
    RefineFace {
        #[arg(short, long)]
        user: Option<String>,
        #[arg(help = "要优化的人脸名称", add = ArgValueCompleter::new(face_completer))]
        face: String,
    },
    /// 列出用户已录入的人脸档案
    ListFaces {
        #[arg(short, long)]
        user: Option<String>,
    },
    /// 删除用户的人脸档案
    RemoveFace {
        #[arg(short, long)]
        user: Option<String>,
        #[arg(help = "要删除的人脸名称", add = ArgValueCompleter::new(face_completer))]
        face: String,
    },
    /// 重命名人脸档案
    RenameFace {
        #[arg(short, long)]
        user: Option<String>,
        #[arg(help = "当前人脸名称", add = ArgValueCompleter::new(face_completer))]
        from: String,
        #[arg(help = "新人脸名称")]
        to: String,
    },
    /// 删除用户的所有 Gaze 数据
    ClearUser {
        #[arg(short, long)]
        user: Option<String>,
    },
    /// 显示或清除胁迫信号触发的人脸认证锁定
    Duress {
        #[arg(long, help = "解除胁迫锁定，重新启用人脸认证")]
        clear: bool,
        #[arg(short, long)]
        user: Option<String>,
    },
    /// 交互式配置守护进程和 GDM 设置
    Config {
        #[arg(long, help = "显示当前值并退出")]
        show: bool,
    },
    /// 录入或替换受 TPM 保护的 GNOME 钥匙环或 KWallet 凭据（仅限 root）
    Keyring {
        /// 使用 KDE KWallet 存储凭据，而非 GNOME 钥匙环
        #[arg(long)]
        kwallet: bool,
        /// 删除已存储的凭据，而非录入凭据
        #[arg(long)]
        forget: bool,
        #[arg(short, long, help = "操作此用户，而非当前用户")]
        user: Option<String>,
    },
    /// 检查 Gaze 安装中的配置和运行问题
    Doctor {
        #[arg(short, long, help = "检查此用户的录入信息")]
        user: Option<String>,
        #[arg(short, long, help = "测试检测器、识别器和活体模型的推理速度")]
        benchmark: bool,
    },
    /// 删除 Gaze 软件包、PAM 集成、配置、模型和用户数据
    Uninstall {
        #[arg(short = 'y', long, help = "跳过确认提示")]
        yes: bool,
        #[arg(long, help = "保留 /var/lib/gaze（已录入的人脸数据）")]
        keep_data: bool,
        #[arg(long, help = "显示计划执行的命令，但不执行")]
        dry_run: bool,
    },
}

fn localized_command(command: clap::Command) -> clap::Command {
    let has_version = command.get_version().is_some();
    let mut command = command
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .help_template("{about-with-newline}\n用法：{usage}\n\n{all-args}")
        .subcommand_help_heading("命令")
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(clap::ArgAction::Help)
                .help("显示帮助"),
        );
    if has_version {
        command = command.arg(
            clap::Arg::new("version")
                .short('V')
                .long("version")
                .action(clap::ArgAction::Version)
                .help("显示版本"),
        );
    }
    command
        .mut_args(|arg| {
            let positional = arg.is_positional();
            arg.help_heading(if positional { "参数" } else { "选项" })
        })
        .mut_subcommands(localized_command)
}

fn parse_cli() -> Cli {
    let matches = localized_command(Cli::command())
        .try_get_matches()
        .unwrap_or_else(|error| {
            let mut message = error.to_string();
            for (english, chinese) in [
                ("error:", "错误："),
                ("Usage:", "用法："),
                (
                    "For more information, try '--help'.",
                    "如需更多信息，请使用 '--help'。",
                ),
                (
                    "the following required arguments were not provided:",
                    "未提供以下必需参数：",
                ),
                ("unexpected argument", "意外的参数"),
                ("found", "不受支持"),
                ("unrecognized subcommand", "无法识别的子命令"),
                ("cannot be used with", "不能与以下参数同时使用："),
                ("the argument", "参数"),
                ("a value is required for", "此参数需要一个值："),
                ("but none was supplied", "但未提供任何值"),
                ("tip:", "提示："),
                ("a similar subcommand exists:", "存在相似的子命令："),
                ("a similar argument exists:", "存在相似的参数："),
                ("to pass", "若要将"),
                ("as a value, use", "作为值传入，请使用"),
                ("[OPTIONS]", "[选项]"),
                ("<COMMAND>", "<命令>"),
            ] {
                message = message.replace(english, chinese);
            }
            if error.use_stderr() {
                eprint!("{message}");
            } else {
                print!("{message}");
            }
            std::process::exit(error.exit_code());
        });
    Cli::from_arg_matches(&matches).expect("已验证的命令行参数")
}

fn ensure_configured_source_listed(options: &mut Vec<(String, String)>, configured: &str) {
    let configured = configured.trim();
    if configured.is_empty() || gaze_vision::camera::is_listed_source(options, configured) {
        return;
    }
    options.push((format!("{configured}（已配置）"), configured.to_string()));
}

fn prompt_security_threshold(
    theme: &ColorfulTheme,
    spectrum: &str,
    default: f64,
) -> anyhow::Result<f64> {
    let value = Input::<String>::with_theme(theme)
        .with_prompt(format!(
            "自定义 {spectrum} 阈值（{MIN_SECURITY_THRESHOLD}–{MAX_SECURITY_THRESHOLD}）"
        ))
        .default(default.to_string())
        .validate_with(|input: &String| match input.trim().parse::<f64>() {
            Ok(value)
                if value.is_finite()
                    && (MIN_SECURITY_THRESHOLD..=MAX_SECURITY_THRESHOLD).contains(&value) =>
            {
                Ok(())
            }
            Ok(_) => Err(format!(
                "必须介于 {MIN_SECURITY_THRESHOLD} 和 {MAX_SECURITY_THRESHOLD} 之间"
            )),
            Err(_) => Err("必须是数字".to_string()),
        })
        .interact_text()?
        .trim()
        .parse::<f64>()
        .unwrap_or(DEFAULT_SECURITY_THRESHOLD);
    Ok(value)
}

async fn run_config_wizard(
    term: &Term,
    proxy: &GazeProxy<'_>,
    mut config: Config,
    keyring_supported: gaze_core::dbus::KeyringSupport,
) -> anyhow::Result<()> {
    let theme = ColorfulTheme::default();

    term.write_line(&format!("\n{}\n", style("Gaze 配置向导").cyan().bold()))?;

    let selected = Select::with_theme(&theme)
        .with_prompt("安全级别")
        .items(SECURITY_LEVEL_LABELS)
        .default(config.security.level_index() as usize)
        .interact()?;

    if let Some(level) = SecurityLevel::preset_from_index(selected) {
        config.security = level;
    } else {
        let seed = config.security.custom_form();

        let selected_det_idx = Select::with_theme(&theme)
            .with_prompt("自定义检测器级别")
            .items(MODEL_QUALITY_LABELS)
            .default(SecurityLevel::model_quality_index(&seed.detector) as usize)
            .interact()?;
        let detector = SecurityLevel::model_quality_from_index(selected_det_idx).to_string();

        let selected_rec_idx = Select::with_theme(&theme)
            .with_prompt("自定义识别器级别")
            .items(MODEL_QUALITY_LABELS)
            .default(SecurityLevel::model_quality_index(&seed.recognizer) as usize)
            .interact()?;
        let recognizer = SecurityLevel::model_quality_from_index(selected_rec_idx).to_string();

        let rgb_threshold = prompt_security_threshold(&theme, "RGB", seed.rgb_threshold)?;
        let ir_threshold = prompt_security_threshold(&theme, "IR", seed.ir_threshold)?;

        let selected_hybrid_idx = Select::with_theme(&theme)
            .with_prompt("自定义混合判定策略")
            .items(HYBRID_POLICY_LABELS)
            .default(SecurityLevel::hybrid_policy_index_for_value(&seed.hybrid_policy) as usize)
            .interact()?;
        let hybrid_policy = SecurityLevel::hybrid_policy_from_index(selected_hybrid_idx);

        config.security = SecurityLevel::custom_with_thresholds(
            detector,
            recognizer,
            rgb_threshold,
            ir_threshold,
            hybrid_policy,
        );
    };

    if config.inference.is_representable() {
        let selected_execution_provider = Select::with_theme(&theme)
            .with_prompt("推理执行后端")
            .items(gaze_core::config::INFERENCE_EXECUTION_PROVIDER_LABELS)
            .default(config.inference.execution_provider_index() as usize)
            .interact()?;
        config.inference.execution_provider =
            gaze_core::config::InferenceConfig::execution_provider_from_index(
                selected_execution_provider,
            )
            .to_string();

        if config.inference.execution_provider == "openvino" {
            let selected_device = Select::with_theme(&theme)
                .with_prompt("OpenVINO 推理设备")
                .items(gaze_core::config::INFERENCE_DEVICE_LABELS)
                .default(config.inference.device_index() as usize)
                .interact()?;
            config.inference.device =
                gaze_core::config::InferenceConfig::device_from_index(selected_device).to_string();
        } else {
            config.inference.device = if matches!(
                config.inference.execution_provider.as_str(),
                "auto" | "vitis"
            ) {
                "npu"
            } else {
                "cpu"
            }
            .to_string();
        }
    } else {
        term.write_line(&format!(
            "{} 保留推理配置 {}/{}：此版本无法修改该配置",
            style("!").yellow().bold(),
            config.inference.execution_provider,
            config.inference.device
        ))?;
    }

    let mut cameras = gaze_vision::camera::enumerate_cameras().unwrap_or_default();
    if cameras.is_empty() {
        anyhow::bail!("未检测到 PipeWire 摄像头！请确认视频输入设备已启用。");
    }
    ensure_configured_source_listed(&mut cameras, &config.cameras.rgb);
    let cam_names: Vec<String> = cameras.iter().map(|(n, _)| n.clone()).collect();
    let default_cam_idx = gaze_vision::camera::source_index(&cameras, &config.cameras.rgb);

    let selected_cam_idx = Select::with_theme(&theme)
        .with_prompt("RGB 摄像头来源")
        .items(&cam_names)
        .default(default_cam_idx)
        .interact()?;

    config.cameras.rgb = cameras[selected_cam_idx].1.clone();

    config.cameras.dark_luma_threshold = Input::<u8>::with_theme(&theme)
        .with_prompt("暗光阈值：拒绝平均亮度低于此值的帧（0–255）")
        .default(config.cameras.dark_luma_threshold)
        .interact_text()?;

    let mut ir_options = gaze_vision::camera::ir_choices();
    ensure_configured_source_listed(&mut ir_options, &config.cameras.ir);

    let ir_names: Vec<String> = ir_options.iter().map(|(n, _)| n.clone()).collect();
    let default_ir_idx = gaze_vision::camera::source_index(&ir_options, &config.cameras.ir);

    let selected_ir_idx = Select::with_theme(&theme)
        .with_prompt("红外摄像头来源")
        .items(&ir_names)
        .default(default_ir_idx)
        .interact()?;

    config.cameras.ir = ir_options[selected_ir_idx].1.clone();

    if config.cameras.ir.is_empty() {
        config.cameras.emitter_enabled = false;
        config.cameras.parallel_capture = "never".to_string();
    } else {
        config.cameras.emitter_enabled = Confirm::with_theme(&theme)
            .with_prompt("强制开启红外发射器（仅在发射器无法自动开启时使用）")
            .default(config.cameras.emitter_enabled)
            .interact()?;

        let capture_idx = Select::with_theme(&theme)
            .with_prompt("同时采集 RGB 和红外画面（速度更快，但部分摄像头不支持）")
            .items(gaze_core::config::PARALLEL_CAPTURE_LABELS.as_slice())
            .default(config.cameras.parallel_capture_index() as usize)
            .interact()?;
        config.cameras.parallel_capture =
            gaze_core::config::CameraConfig::parallel_capture_from_index(capture_idx);
    }

    config.auth.abort_if_ssh = Confirm::with_theme(&theme)
        .with_prompt("SSH 会话中中止人脸认证")
        .default(config.auth.abort_if_ssh)
        .interact()?;

    config.auth.abort_if_lid_closed = Confirm::with_theme(&theme)
        .with_prompt("笔记本合盖时中止人脸认证")
        .default(config.auth.abort_if_lid_closed)
        .interact()?;

    config.auth.abort_before_first_resume = Confirm::with_theme(&theme)
        .with_prompt("系统完成一次挂起并恢复前中止人脸认证")
        .default(config.auth.abort_before_first_resume)
        .interact()?;

    config.auth.require_confirmation_lock_screen = Confirm::with_theme(&theme)
        .with_prompt("锁屏界面匹配到人脸后需要确认（按 Enter 或点击认证/确定）")
        .default(config.auth.require_confirmation_lock_screen)
        .interact()?;

    config.auth.require_confirmation_elevation = Confirm::with_theme(&theme)
        .with_prompt("提权认证（sudo、polkit 等）匹配到人脸后需要确认（按 Enter 或点击认证/确定）")
        .default(config.auth.require_confirmation_elevation)
        .interact()?;

    config.auth.resume_grace_ms = Input::with_theme(&theme)
        .with_prompt("唤醒宽限时间，单位为毫秒（挂起恢复后延迟认证）")
        .default(config.auth.resume_grace_ms)
        .interact_text()?;

    config.auth.start_delay_ms = Input::with_theme(&theme)
        .with_prompt("启动延迟，单位为毫秒（0 表示禁用）")
        .default(config.auth.start_delay_ms)
        .interact_text()?;

    if config.auth.start_delay_ms > 0 {
        let scope_index = Select::with_theme(&theme)
            .with_prompt("启动延迟适用范围")
            .items(START_DELAY_SCOPE_LABELS)
            .default(
                AuthConfig::start_delay_scope_index_for_value(config.auth.start_delay_scope())
                    as usize,
            )
            .interact()?;
        config.auth.start_delay_scope = AuthConfig::start_delay_scope_from_index(scope_index);
    }

    config.enrollment.max_templates = Input::with_theme(&theme)
        .with_prompt("模板数量上限（采集组数）")
        .default(config.enrollment.max_templates)
        .interact_text()?;

    let min_face_size_ratio: f64 = Input::with_theme(&theme)
        .with_prompt("录入时的最小人脸尺寸比例（0.10–0.75；降低此值可增加距离）")
        .default(config.enrollment.min_face_size_ratio)
        .interact_text()?;
    config.enrollment.min_face_size_ratio = if min_face_size_ratio.is_finite() {
        min_face_size_ratio.clamp(
            MIN_ENROLLMENT_FACE_SIZE_RATIO,
            MAX_ENROLLMENT_FACE_SIZE_RATIO,
        )
    } else {
        config.enrollment.effective_min_face_size_ratio() as f64
    };

    config.liveness.enabled = Confirm::with_theme(&theme)
        .with_prompt("启用活体防伪检测")
        .default(config.liveness.enabled)
        .interact()?;
    if config.liveness.enabled {
        config.liveness.threshold = Input::<String>::with_theme(&theme)
            .with_prompt(format!(
                "活体检测阈值（{}–{}）",
                MIN_LIVENESS_THRESHOLD, MAX_LIVENESS_THRESHOLD
            ))
            .default(config.liveness.threshold.to_string())
            .validate_with(|input: &String| match input.trim().parse::<f64>() {
                Ok(value)
                    if value.is_finite()
                        && (MIN_LIVENESS_THRESHOLD..=MAX_LIVENESS_THRESHOLD).contains(&value) =>
                {
                    Ok(())
                }
                Ok(_) => Err(format!(
                    "必须介于 {MIN_LIVENESS_THRESHOLD} 和 {MAX_LIVENESS_THRESHOLD} 之间"
                )),
                Err(_) => Err("必须是数字".to_string()),
            })
            .interact_text()?
            .trim()
            .parse::<f64>()
            .unwrap_or(0.8);
        config.liveness.max_seconds = Input::with_theme(&theme)
            .with_prompt(format!(
                "最长活体检测秒数（{MIN_LIVENESS_MAX_SECONDS}..={MAX_LIVENESS_MAX_SECONDS}）"
            ))
            .default(config.liveness.max_seconds)
            .validate_with(|value: &f64| {
                if *value >= MIN_LIVENESS_MAX_SECONDS && *value <= MAX_LIVENESS_MAX_SECONDS {
                    Ok(())
                } else {
                    Err(format!(
                        "必须介于 {MIN_LIVENESS_MAX_SECONDS} 和 {MAX_LIVENESS_MAX_SECONDS} 之间"
                    ))
                }
            })
            .interact_text()?;
    }

    config.storage.encrypt_templates = Confirm::with_theme(&theme)
        .with_prompt("使用 TPM 2.0 加密存储的人脸模板")
        .default(config.storage.encrypt_templates)
        .interact()?;

    config.storage.unlock_gnome_keyring =
        if keyring_supported.gnome && config.storage.encrypt_templates && config.liveness.enabled {
            Confirm::with_theme(&theme)
                .with_prompt("为 GDM 或 greetd 人脸登录启用 TPM 保护的 GNOME 钥匙环解锁")
                .default(config.storage.unlock_gnome_keyring)
                .interact()?
        } else {
            false
        };

    config.storage.unlock_kwallet =
        if keyring_supported.kwallet && config.storage.encrypt_templates && config.liveness.enabled
        {
            Confirm::with_theme(&theme)
                .with_prompt("为 KDE 人脸登录启用 TPM 保护的 KWallet 解锁")
                .default(config.storage.unlock_kwallet)
                .interact()?
        } else {
            false
        };

    let saved = if keyring_supported.gnome || keyring_supported.kwallet {
        apply_config_with_keyring_to_daemon(proxy, &config).await
    } else {
        apply_config_to_daemon(proxy, &config).await
    };
    saved.map_err(|e| anyhow::anyhow!("无法保存配置：{e}"))?;
    term.write_line(&format!("{} 配置已保存并应用。", style("✓").green().bold()))?;

    if config.storage.unlock_gnome_keyring
        && Confirm::with_theme(&theme)
            .with_prompt("现在录入登录钥匙环密码")
            .default(false)
            .interact()?
    {
        keyring::enroll(
            &get_current_user(),
            &config,
            gaze_security::keyring::Backend::Gnome,
        )?;
    }

    if config.storage.unlock_kwallet
        && Confirm::with_theme(&theme)
            .with_prompt("现在录入 KWallet 密码")
            .default(false)
            .interact()?
    {
        keyring::enroll(
            &get_current_user(),
            &config,
            gaze_security::keyring::Backend::KWallet,
        )?;
    }

    Ok(())
}

async fn handle_enroll(
    proxy: &GazeProxy<'_>,
    user: &str,
    face: &str,
    is_refine: bool,
) -> anyhow::Result<()> {
    let term = Term::stdout();

    if let Err(err) = proxy.claim(user).await {
        term.write_line(&format!(
            "{} 无法取得设备使用权：{}",
            style("✗").red().bold(),
            dbus_error_message(&err)
        ))?;
        std::process::exit(1);
    }

    let mut enroll_stream = proxy.receive_enroll_status().await?;
    let mut capture_stream = proxy.receive_face_status().await?;
    let mut terminal = match TuiTerminal::new() {
        Ok(terminal) => terminal,
        Err(err) => {
            let _ = proxy.release().await;
            return Err(err);
        }
    };
    if let Err(err) = proxy.enroll_start(face).await {
        drop(terminal);
        let _ = proxy.release().await;
        anyhow::bail!("无法开始录入：{}", dbus_error_message(&err));
    }

    let mut current_enroll_msg = "正在等待采集提示".to_string();
    let mut current_capture_msg = "正在等待人脸...".to_string();
    let mut current_capture_tone = Tone::Info;
    let mut current_progress = 0_u32;
    let mut current_max = 100_u32;
    let mut current_time_remaining = None;
    let mut confirm_cancel = false;
    let mut tick = 0_u64;

    let mut is_cancelled = false;
    let mut is_completed = false;
    let mut is_failed = false;
    loop {
        terminal.draw_enroll(&EnrollScreen {
            user,
            face,
            is_refine,
            prompt: &current_enroll_msg,
            capture: &current_capture_msg,
            capture_tone: current_capture_tone,
            progress: current_progress,
            max: current_max,
            time_remaining: current_time_remaining,
            confirm_cancel,
            tick,
        })?;

        if tui::apply_cancel_action(&mut confirm_cancel, tui::poll_action()?)
            == tui::ConfirmStep::CancelConfirmed
        {
            is_cancelled = true;
            break;
        }

        tokio::select! {
            signal = enroll_stream.next() => match signal {
                Some(signal) => {
                    if let Ok(args) = signal.args() {
                        let raw_msg = *args.msg();
                        let time_remaining = *args.time_remaining();
                        let is_done = *args.is_done();
                        current_progress = *args.progress();
                        current_max = *args.max();
                        current_enroll_msg = raw_msg.to_string();
                        current_time_remaining = (time_remaining > 0.0).then_some(time_remaining);

                        if matches!(raw_msg, EnrollPrompt::DbFailed | EnrollPrompt::CameraFailed | EnrollPrompt::Cancelled) {
                            is_failed = true;
                            break;
                        }

                        if is_done && raw_msg == EnrollPrompt::Completed {
                            is_completed = true;
                            break;
                        }

                        if is_done {
                            is_failed = true;
                            break;
                        }
                    }
                }
                None => {
                    is_failed = true;
                    break;
                }
            },
            signal = capture_stream.next() => {
                if let Some(signal) = signal
                    && let Ok(args) = signal.args()
                {
                    let status = *args.status();
                    current_capture_msg = status.to_string();
                    current_capture_tone = capture_tone(status);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(80)) => {
                tick = tick.wrapping_add(1);
            }
        }
    }

    drop(terminal);

    if is_cancelled {
        let _ = proxy.enroll_stop().await;
    }
    let _ = proxy.release().await;
    if is_cancelled {
        term.write_line(&format!("\n{} 录入已取消", style("✗").red().bold()))?;
        std::process::exit(130);
    }
    if is_completed {
        term.write_line(&format!(
            "  {} 已保存 {}/{} 的采集数据！\n",
            style("✓").green().bold(),
            style(user).green(),
            style(face).green()
        ))?;
    } else if is_failed {
        term.write_line(&format!(
            "{} 录入失败：{}",
            style("✗").red().bold(),
            current_enroll_msg
        ))?;
        std::process::exit(1);
    }
    Ok(())
}

async fn handle_auth(
    proxy: &GazeProxy<'_>,
    user: &str,
    verbose: bool,
    silent: bool,
) -> anyhow::Result<()> {
    let term = Term::stdout();

    let has_faces = match proxy.list_faces(user).await {
        Ok(faces) => !faces.is_empty(),
        Err(ref e) if gaze_core::dbus::dbus_is_file_not_found(e) => false,
        Err(e) => return Err(e.into()),
    };
    if !has_faces {
        if !silent {
            term.write_line(&format!(
                "{} 尚未为 {} 录入人脸。请运行 {} 录入人脸。",
                style("i").cyan().bold(),
                style(user).bold(),
                style("gaze add-face <name>").bold()
            ))?;
        }
        std::process::exit(1);
    }

    let start = std::time::Instant::now();

    if let Err(err) = proxy.claim(user).await {
        if !silent {
            term.write_line(&format!(
                "{} 无法取得设备使用权：{}",
                style("✗").red().bold(),
                dbus_error_message(&err)
            ))?;
        }
        std::process::exit(1);
    }

    let mut status_stream = proxy.receive_verify_status().await?;
    let mut capture_stream = proxy.receive_face_status().await?;
    let mut diagnostic_stream = proxy.receive_verify_diagnostic().await?;
    let mut terminal = if !silent {
        match TuiTerminal::new() {
            Ok(terminal) => Some(terminal),
            Err(err) => {
                let _ = proxy.release().await;
                return Err(err);
            }
        }
    } else {
        None
    };

    if let Err(e) = proxy.verify_start("any").await {
        drop(terminal);
        if !silent {
            term.write_line(&format!("{} 守护进程错误：{}", style("✗").red().bold(), e))?;
        }
        let _ = proxy.release().await;
        std::process::exit(1);
    }

    let mut status_msg = format!("正在扫描 {user} 的人脸...");
    let mut status_tone = Tone::Info;
    let mut tick = 0_u64;
    let mut cancelled = false;
    let mut timed_out = false;
    let mut verify_result = None;
    let mut diagnostics = Vec::new();
    let deadline = tokio::time::Instant::now() + gaze_core::dbus::VERIFY_CLIENT_TIMEOUT;

    loop {
        if let Some(ref mut terminal) = terminal {
            terminal.draw_auth(&AuthScreen {
                user,
                status: &status_msg,
                status_tone,
                elapsed: start.elapsed(),
                tick,
            })?;

            if let Some(TuiAction::Cancel) = tui::poll_action()? {
                cancelled = true;
                break;
            }
        }

        tokio::select! {
            signal = status_stream.next() => {
                let Some(signal) = signal else { break };
                if let Ok(args) = signal.args() {
                    verify_result = Some((*args.result(), args.faces().clone(), *args.rgb_status(), *args.ir_status()));
                    break;
                }
            }
            signal = capture_stream.next() => {
                let Some(signal) = signal else { break };
                if let Ok(args) = signal.args() {
                    let status = *args.status();
                    status_tone = capture_tone(status);
                    status_msg = match status {
                        CaptureStatus::Ready | CaptureStatus::Usable => format!("正在扫描 {user} 的人脸..."),
                        _ => status.to_string(),
                    };
                }
            }
        // Collect these even without `--verbose`, so failures can include the latest diagnostic.
            signal = diagnostic_stream.next() => {
                let Some(signal) = signal else { break };
                if let Ok(args) = signal.args() {
                    diagnostics.push(args.message().to_string());
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                timed_out = true;
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(80)) => {
                tick = tick.wrapping_add(1);
            }
        }
    }

    drop(terminal);

    // A diagnostic sent just before the verdict may still be in flight. Since the streams are
    // separate, this one can explain the result even if it arrives after the verdict.
    while let Ok(Some(signal)) =
        tokio::time::timeout(Duration::from_millis(20), diagnostic_stream.next()).await
    {
        if let Ok(args) = signal.args() {
            diagnostics.push(args.message().to_string());
        }
    }

    if cancelled {
        let _ = proxy.verify_stop().await;
        let _ = proxy.release().await;
        std::process::exit(130);
    }

    if timed_out {
        let _ = proxy.verify_stop().await;
        let _ = proxy.release().await;
        if !silent {
            term.write_line(&format!(
                "{} 等待守护进程判定超时（{}毫秒）",
                style("✗").red().bold(),
                start.elapsed().as_millis()
            ))?;
        }
        std::process::exit(1);
    }

    let mut authenticated = false;
    if let Some((result, faces, rgb_status, ir_status)) = verify_result {
        if verbose {
            for message in &diagnostics {
                println!("{message}");
            }
            if !diagnostics.is_empty() {
                println!();
            }
            println!(
                "\n{:<20} {:>10} {:>8} {:>8} {:>10} {:>8} {:>8}",
                style("人脸").bold(),
                style("RGB 相似度").bold(),
                style("RGB %").bold(),
                style("RGB 通过").bold(),
                style("红外相似度").bold(),
                style("红外 %").bold(),
                style("红外通过").bold()
            );
            println!("{}", style("-".repeat(78)).dim());
            for (name, rgb_sim, rgb_pct, rgb_passed, ir_sim, ir_pct, ir_passed) in &faces {
                let rgb_check = if *rgb_passed {
                    style("✓").green()
                } else {
                    style("✗").red()
                };
                let ir_check = if *ir_passed {
                    style("✓").green()
                } else {
                    style("✗").red()
                };
                println!(
                    "{:<20} {:>10.4} {:>7.1}% {:>8} {:>10.4} {:>7.1}% {:>8}",
                    style(name).cyan(),
                    rgb_sim,
                    rgb_pct,
                    rgb_check,
                    ir_sim,
                    ir_pct,
                    ir_check
                );
            }
            println!();

            println!(
                "{} RGB：{} | 红外：{}",
                style("状态：").bold(),
                style(format!("{:?}", rgb_status)).cyan(),
                style(format!("{:?}", ir_status)).cyan()
            );
            println!();
        }

        if result == VerifyResult::VerifyMatch {
            authenticated = true;
            if !silent {
                let matched = faces
                    .iter()
                    .find(|(_, _, _, rgb_p, _, _, ir_p)| *rgb_p || *ir_p)
                    .map(|(n, _, rgb_pct, rgb_p, _, ir_pct, ir_p)| {
                        let pct = if *rgb_p && *ir_p {
                            rgb_pct.max(*ir_pct)
                        } else if *rgb_p {
                            *rgb_pct
                        } else {
                            *ir_pct
                        };
                        (n.clone(), pct)
                    });
                if let Some((face, pct)) = matched {
                    term.write_line(&format!(
                        "{} 已认证为：{}（{:.1}%，{}毫秒）",
                        style("✓").green().bold(),
                        style(&face).green().bold(),
                        pct,
                        start.elapsed().as_millis()
                    ))?;
                } else {
                    term.write_line(&format!(
                        "{} 已认证为：{}（{}毫秒）",
                        style("✓").green().bold(),
                        style(user).green().bold(),
                        start.elapsed().as_millis()
                    ))?;
                }
            }
        }
    }

    if !authenticated && !silent {
        term.write_line(&format!(
            "{} 认证失败（{}毫秒）",
            style("✗").red().bold(),
            start.elapsed().as_millis()
        ))?;
        // "认证失败" alone can sound like a face mismatch even if the camera never
        // opened. Verbose mode has already printed the full diagnostic list.
        if !verbose && let Some(reason) = diagnostics.last() {
            term.write_line(&format!("  {}", style(reason).yellow()))?;
        }
    }

    let _ = proxy.release().await;
    if !authenticated {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpectrumBadge {
    /// The profile holds captures for this spectrum.
    Enrolled,
    /// A camera is configured for this spectrum, but the profile has no captures yet.
    Missing,
    /// No camera for this spectrum, so there is nothing to enroll.
    Unused,
}

/// A spectrum without a configured camera is not missing from the profile.
/// Describe it as unconfigured rather than incomplete.
fn spectrum_badge_state(enrolled: bool, configured: bool) -> SpectrumBadge {
    match (enrolled, configured) {
        (true, _) => SpectrumBadge::Enrolled,
        (false, true) => SpectrumBadge::Missing,
        (false, false) => SpectrumBadge::Unused,
    }
}

fn spectrum_badge(label: &str, enrolled: bool, configured: bool) -> String {
    let badge = format!("[{label}]");
    match spectrum_badge_state(enrolled, configured) {
        SpectrumBadge::Enrolled => style(badge).green().bold().to_string(),
        SpectrumBadge::Missing => style(badge).yellow().bold().to_string(),
        SpectrumBadge::Unused => style(badge).dim().to_string(),
    }
}

fn write_no_faces(term: &Term, user: &str) -> anyhow::Result<()> {
    term.write_line(&format!(
        "{} 未找到 {} 的人脸",
        style("i").cyan().bold(),
        style(user).bold()
    ))?;
    Ok(())
}

async fn handle_list_faces(proxy: &GazeProxy<'_>, user: &str) -> anyhow::Result<()> {
    let term = Term::stdout();
    let cameras = try_load_config_from_daemon(proxy)
        .await
        .ok()
        .flatten()
        .map(|config| {
            (
                !config.cameras.rgb.trim().is_empty(),
                !config.cameras.ir.trim().is_empty(),
            )
        });
    let (rgb_configured, ir_configured) = cameras.unwrap_or((true, true));
    let result = run_busy(
        "人脸数据库",
        format!("正在获取 {user} 的人脸..."),
        Tone::Info,
        proxy.list_faces(user),
    )
    .await?;

    match result {
        Ok(faces) => {
            if faces.is_empty() {
                write_no_faces(&term, user)?;
            } else {
                term.write_line(&format!(
                    "\n{} 个人脸，用户 {}：\n",
                    style(faces.len()).green().bold(),
                    style(user).bold()
                ))?;
                for (face, count, has_rgb, has_ir) in faces {
                    let rgb_badge = spectrum_badge("RGB", has_rgb, rgb_configured);
                    let ir_badge = spectrum_badge("IR", has_ir, ir_configured);
                    term.write_line(&format!(
                        "  {} {} {} {}（{} 组采集）",
                        style("•").cyan(),
                        style(face).bold(),
                        rgb_badge,
                        ir_badge,
                        count
                    ))?;
                }
                term.write_line("")?;
            }
        }
        Err(e) => {
            if dbus_is_file_not_found(&e) {
                write_no_faces(&term, user)?;
            } else {
                term.write_line(&format!(
                    "{} 无法获取人脸：{}",
                    style("✗").red().bold(),
                    dbus_error_message(&e)
                ))?;
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn handle_remove_face(proxy: &GazeProxy<'_>, user: &str, face: &str) -> anyhow::Result<()> {
    let term = Term::stdout();
    let result = run_busy(
        "删除人脸",
        format!("正在删除人脸 {face}..."),
        Tone::Warn,
        proxy.delete_face(user, face),
    )
    .await?;

    match result {
        Ok(true) => {
            term.write_line(&format!(
                "{} 已删除人脸 '{}'，用户 '{}'",
                style("✓").green().bold(),
                face,
                user
            ))?;
        }
        Ok(false) => {
            term.write_line(&format!(
                "{} 未找到人脸 '{}'，用户 '{}'",
                style("!").yellow().bold(),
                face,
                user
            ))?;
        }
        Err(err) => {
            term.write_line(&format!(
                "{} 无法删除人脸：{}",
                style("✗").red().bold(),
                dbus_error_message(&err)
            ))?;
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn handle_rename_face(
    proxy: &GazeProxy<'_>,
    user: &str,
    from: &str,
    to: &str,
) -> anyhow::Result<()> {
    let term = Term::stdout();
    let result = run_busy(
        "重命名人脸",
        format!("正在重命名人脸 {from} -> {to}..."),
        Tone::Info,
        proxy.rename_face(user, from, to),
    )
    .await?;

    match result {
        Ok(true) => {
            term.write_line(&format!(
                "{} 已将人脸 '{}' 重命名为 '{}'，用户 '{}'",
                style("✓").green().bold(),
                from,
                to,
                user
            ))?;
        }
        Ok(false) => {
            term.write_line(&format!(
                "{} 未找到人脸 '{}'，用户 '{}'",
                style("!").yellow().bold(),
                from,
                user
            ))?;
        }
        Err(err) => {
            term.write_line(&format!(
                "{} 无法重命名人脸：{}",
                style("✗").red().bold(),
                dbus_error_message(&err)
            ))?;
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn handle_duress(proxy: &GazeProxy<'_>, user: &str, clear: bool) -> anyhow::Result<()> {
    let term = Term::stdout();
    if clear {
        let cleared = proxy
            .clear_duress(user)
            .await
            .map_err(|err| anyhow::anyhow!("无法解除胁迫锁定：{}", dbus_error_message(&err)))?;
        if cleared {
            term.write_line(&format!("已为 {} 重新启用人脸认证。", style(user).bold()))?;
        } else {
            term.write_line(&format!("{} 的人脸认证未被锁定。", style(user).bold()))?;
        }
        return Ok(());
    }

    let locked = proxy
        .duress_locked(user)
        .await
        .map_err(|err| anyhow::anyhow!("无法读取胁迫锁定状态：{}", dbus_error_message(&err)))?;
    if locked {
        term.write_line(&format!(
            "收到胁迫信号后，{} 的人脸认证已{}。请使用密码登录，或运行 `gaze duress --clear`。",
            style(user).bold(),
            style("锁定").red().bold()
        ))?;
    } else {
        term.write_line(&format!(
            "{} 的人脸认证{}。",
            style(user).bold(),
            style("未锁定").green()
        ))?;
    }
    Ok(())
}

async fn handle_clear_user(proxy: &GazeProxy<'_>, user: &str) -> anyhow::Result<()> {
    let term = Term::stdout();
    let result = run_busy(
        "清除用户",
        format!("正在删除 {user} 的所有数据..."),
        Tone::Warn,
        proxy.delete_faces(user),
    )
    .await?;

    match result {
        Ok(_) => {
            gaze_security::keyring::forget(user)
                .and_then(|()| {
                    gaze_security::keyring::forget_for(
                        gaze_security::keyring::Backend::KWallet,
                        user,
                    )
                })
                .map_err(|err| {
                    anyhow::anyhow!(
                        "人脸数据已清除，但无法删除用户 '{user}' 已存储的钥匙环凭据：{err}"
                    )
                })?;
            term.write_line(&format!(
                "{} 已清除 '{}' 的所有数据",
                style("✓").green().bold(),
                user
            ))?;
        }
        Err(err) => {
            term.write_line(&format!(
                "{} 无法清除用户：{}",
                style("✗").red().bold(),
                dbus_error_message(&err)
            ))?;
            std::process::exit(1);
        }
    }
    Ok(())
}

fn which(bin: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn reset_gnome_user_settings_cmd() -> String {
    [
        "if command -v getent >/dev/null 2>&1 && command -v dbus-run-session >/dev/null 2>&1; then",
        "getent passwd | while IFS=: read -r user _ uid _ _ home _; do",
        r#"{ [ "$uid" -ge 1000 ] 2>/dev/null || [ "$user" = gdm ] || [ "$user" = gdm3 ] || [ "$user" = Debian-gdm ]; } || continue;"#,
        r#"[ -d "$home" ] || continue;"#,
        r#"dconf_profile="";"#,
        r#"case "$user" in gdm|gdm3|Debian-gdm) dconf_profile="DCONF_PROFILE=gdm" ;; esac;"#,
        r#"sudo -u "$user" env HOME="$home" $dconf_profile dbus-run-session sh -c 'EXT_ID="gaze@gundulabs.com";"#,
        "if command -v gsettings >/dev/null 2>&1; then",
        "current=$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null || true);",
        r#"case "$current" in *"$EXT_ID"*)"#,
        r#"next=$(printf "%s" "$current" | sed "s/\047$EXT_ID\047, //; s/, \047$EXT_ID\047//; s/\047$EXT_ID\047//");"#,
        r#"gsettings set org.gnome.shell enabled-extensions "$next" 2>/dev/null || true;;"#,
        "esac;",
        "gsettings reset-recursively org.gnome.shell.extensions.gaze 2>/dev/null || true;",
        "fi;",
        "if command -v dconf >/dev/null 2>&1; then",
        "dconf reset -f /org/gnome/shell/extensions/gaze/ 2>/dev/null || true;",
        "fi' || true;",
        "done; fi",
    ]
    .join(" ")
}

fn remove_gdm_dconf_overrides_cmd() -> String {
    [
        "sudo rm -f /etc/dconf/db/gdm.d/*gaze* &&",
        "if command -v dconf >/dev/null 2>&1; then",
        "sudo dconf update >/dev/null 2>&1 || true;",
        "fi",
    ]
    .join(" ")
}

fn restore_authselect_cmd() -> String {
    [
        "if [ -f /etc/gaze/authselect.previous ]; then",
        r#"profile=$(sudo sed -n 's/^Profile ID:[[:space:]]*//p' /etc/gaze/authselect.previous);"#,
        r#"features=$(sudo sed -n 's/^- //p' /etc/gaze/authselect.previous | tr '\n' ' ');"#,
        r#"if [ -n "$profile" ]; then"#,
        r#"sudo authselect select "$profile" $features --force 2>/dev/null || true;"#,
        "else",
        "sudo authselect select sssd --force 2>/dev/null || true;",
        "fi;",
        "else",
        "sudo authselect select sssd --force 2>/dev/null || true;",
        "fi",
    ]
    .join(" ")
}

fn refresh_gnome_system_settings_cmd() -> String {
    [
        "if command -v dconf >/dev/null 2>&1; then",
        "sudo dconf update >/dev/null 2>&1 || true;",
        "fi;",
        "if command -v glib-compile-schemas >/dev/null 2>&1; then",
        "sudo glib-compile-schemas /usr/share/glib-2.0/schemas >/dev/null 2>&1 || true;",
        "fi",
    ]
    .join(" ")
}

fn remove_unmanaged_install_artifacts_cmd() -> String {
    [
        r#"owned_by_pkg() {
          p=$1;
          if command -v pacman >/dev/null 2>&1; then pacman -Qo "$p" >/dev/null 2>&1 && return 0; fi;
          if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -S "$p" >/dev/null 2>&1 && return 0; fi;
          if command -v rpm >/dev/null 2>&1; then rpm -qf "$p" >/dev/null 2>&1 && return 0; fi;
          return 1;
        };
        remove_if_unmanaged() {
          p=$1;
          [ -e "$p" ] || [ -L "$p" ] || return 0;
          if [ -L "$p" ] || ! owned_by_pkg "$p"; then
            sudo rm -rf "$p";
          fi;
        };
        for p in \
          /usr/bin/gaze /usr/bin/gazed /usr/bin/gaze-gui \
          /usr/local/bin/gaze /usr/local/bin/gazed /usr/local/bin/gaze-gui \
          /usr/lib/security/pam_gaze.so /usr/lib/security/pam_gaze_grosshack.so \
          /usr/lib64/security/pam_gaze.so /usr/lib64/security/pam_gaze_grosshack.so \
          /usr/share/glib-2.0/schemas/org.gnome.shell.extensions.gaze.gschema.xml \
          /usr/share/polkit-1/actions/com.gundulabs.gaze.policy \
          /usr/share/gnome-shell/extensions/gaze@gundulabs.com/extension.js \
          /usr/share/gnome-shell/extensions/gaze@gundulabs.com/metadata.json \
          /usr/share/gnome-shell/extensions/gaze@gundulabs.com/prefs.js
        do remove_if_unmanaged "$p"; done;
        for p in /lib/*/security/pam_gaze.so /lib/*/security/pam_gaze_grosshack.so /usr/lib/*/security/pam_gaze.so /usr/lib/*/security/pam_gaze_grosshack.so; do
          [ -e "$p" ] || [ -L "$p" ] || continue;
          remove_if_unmanaged "$p";
        done;
        sudo rmdir /usr/share/gnome-shell/extensions/gaze@gundulabs.com 2>/dev/null || true;
        sudo rm -rf /etc/systemd/system/gazed.service.d;
        sudo rm -rf /usr/local/share/gaze-dev;
        sudo systemctl daemon-reload >/dev/null 2>&1 || true;
        if command -v glib-compile-schemas >/dev/null 2>&1; then sudo glib-compile-schemas /usr/share/glib-2.0/schemas >/dev/null 2>&1 || true; fi"#,
    ]
    .join(" ")
}

fn remove_arch_pam_configuration_cmd() -> String {
    [
        "for flag in /etc/gaze/pam-arch.configured /etc/gaze/pam-arch.dev-configured; do",
        r#"[ -f "$flag" ] || continue;"#,
        r#"while IFS= read -r f; do"#,
        r#"[ -f "$f" ] || continue;"#,
        r#"sudo sed -i '/pam_gaze/d' "$f" || true;"#,
        "done < \"$flag\";",
        "done;",
        "sudo sed -i '/pam_gaze/d' /etc/pam.d/sudo 2>/dev/null || true;",
        "for flag in /etc/gaze/pam-arch.polkit-configured /etc/gaze/pam-arch.polkit-dev-configured; do",
        r#"[ -f "$flag" ] || continue;"#,
        r#"while IFS= read -r f; do"#,
        r#"sudo rm -f "$f" || true;"#,
        "done < \"$flag\";",
        r#"sudo rm -f "$flag" || true;"#,
        "done",
    ]
    .join(" ")
}

fn remove_rpm_ostree_packages_cmd() -> String {
    "sudo rpm-ostree uninstall gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde \
      2>/dev/null || \
      for pkg in gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde; do \
      sudo rpm-ostree uninstall \"$pkg\" 2>/dev/null || true; \
      done"
        .into()
}

fn remove_pacman_packages_cmd() -> String {
    // AUR builds split off `-debug` packages; remove those first since they can
    // depend on the base package.
    "for base in gaze-omarchy-bin gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde gaze-bin gaze-gui-bin \
      gaze-gnome-extension-bin gaze-hyprlock-bin gaze-kde-bin; do \
      for pkg in \"$base-debug\" \"$base\"; do \
      if pacman -Q \"$pkg\" >/dev/null 2>&1; then \
      sudo pacman -Rns --noconfirm \"$pkg\" || true; \
      fi; \
      done; \
      done"
        .into()
}

fn remove_zypper_packages_cmd() -> String {
    // Include every optional openSUSE integration package.
    "sudo zypper --non-interactive remove --no-confirm gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde 2>/dev/null || true"
        .into()
}

fn remove_suse_pam_configuration_cmd() -> String {
    // Remove both managed PAM modes independently.
    "if command -v pam-config >/dev/null 2>&1; then \
      sudo pam-config --delete --gaze 2>/dev/null || true; \
      sudo pam-config --delete --gaze_grosshack 2>/dev/null || true; \
      sudo pam-config --update 2>/dev/null || true; \
      fi"
    .into()
}

const GUNDULABS_REPO_KEY_FINGERPRINT: &str = "505AC1C71AFEDBD5555235F6CB4FA24E5C1C7C98";
// RPM key package versions use the final eight fingerprint characters.

fn remove_zypper_repo_and_key_cmd() -> String {
    // Match only the RPM key package derived from the Gundu Labs fingerprint.
    let key_id = GUNDULABS_REPO_KEY_FINGERPRINT
        .get(GUNDULABS_REPO_KEY_FINGERPRINT.len() - 8..)
        .expect("Gundu Labs fingerprint must contain a key ID")
        .to_ascii_lowercase();
    format!(
        "sudo rm -f /etc/zypp/repos.d/gundulabs.repo \\
          /etc/pki/rpm-gpg/RPM-GPG-KEY-gundulabs; \\
          if command -v rpm >/dev/null 2>&1; then \\
            rpm -qa 'gpg-pubkey*' --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}\\n' 2>/dev/null | \\
            while IFS= read -r key_package; do \\
              case \"$key_package\" in \\
                gpg-pubkey-{key_id}-*) sudo rpm -e \"$key_package\" 2>/dev/null || true ;; \\
              esac; \\
            done; \\
          fi"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageManager {
    Apt,
    Zypper,
    Dnf,
    RpmOstree,
    Pacman,
}

fn append_package_manager_uninstall_steps(
    plan: &mut Vec<(&'static str, String)>,
    package_manager: PackageManager,
) {
    match package_manager {
        PackageManager::Apt => {
            plan.push((
                "删除 apt 软件包",
                "sudo apt-get remove --purge -y gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde 2>/dev/null || true"
                    .into(),
            ));
            plan.push((
                "删除 apt 软件源和密钥环",
                "sudo rm -f /etc/apt/sources.list.d/gundulabs.list \\
                  /usr/share/keyrings/gundulabs-archive-keyring.gpg && \\
                  sudo apt-get update 2>/dev/null || true"
                    .into(),
            ));
        }
        // Prefer Tumbleweed's native package manager.
        PackageManager::Zypper => {
            plan.push((
                "删除 openSUSE PAM 配置",
                remove_suse_pam_configuration_cmd(),
            ));
            plan.push(("删除 zypper 软件包", remove_zypper_packages_cmd()));
            plan.push(("删除 zypper 软件源和密钥", remove_zypper_repo_and_key_cmd()));
        }
        PackageManager::Dnf => {
            plan.push((
                "删除 dnf 软件包",
                "sudo dnf remove -y gaze-omarchy gaze gaze-gui gaze-gnome-extension gaze-hyprlock gaze-kde 2>/dev/null || true"
                    .into(),
            ));
            plan.push((
                "删除 dnf 软件源",
                "sudo rm -f /etc/yum.repos.d/gundulabs.repo".into(),
            ));
        }
        PackageManager::RpmOstree => {
            plan.push(("删除分层软件包", remove_rpm_ostree_packages_cmd()));
            plan.push((
                "删除 dnf 软件源",
                "sudo rm -f /etc/yum.repos.d/gundulabs.repo".into(),
            ));
            plan.push((
                "重启以完成删除",
                "echo '分层软件包将在下次重启后完成删除。'".into(),
            ));
        }
        PackageManager::Pacman => {
            plan.push(("删除 pacman 软件包", remove_pacman_packages_cmd()));
            plan.push((
                "删除旧的 pacman 软件源条目",
                "sudo sed -i '/^\\[gaze\\]/,/^$/d' /etc/pacman.conf && \\
                  sudo rm -f /etc/pacman.d/gaze-mirrorlist"
                    .into(),
            ));
        }
    }
}

fn package_manager_from_availability(
    apt: bool,
    zypper: bool,
    dnf: bool,
    pacman: bool,
    rpm_ostree: bool,
) -> Option<PackageManager> {
    // Prefer zypper when optional apt or dnf tools are also installed.
    if zypper {
        Some(PackageManager::Zypper)
    } else if apt {
        Some(PackageManager::Apt)
    } else if rpm_ostree {
        Some(PackageManager::RpmOstree)
    } else if dnf {
        Some(PackageManager::Dnf)
    } else if pacman {
        Some(PackageManager::Pacman)
    } else {
        None
    }
}

fn detect_package_manager() -> Option<PackageManager> {
    package_manager_from_availability(
        which("apt-get"),
        which("zypper"),
        which("dnf"),
        which("pacman"),
        which("rpm-ostree") && std::path::Path::new("/run/ostree-booted").exists(),
    )
}

const RESTORE_OMARCHY_LOCK_STEP: &str = "删除 Gaze 前恢复原版 Omarchy 锁屏";

fn build_uninstall_plan(keep_data: bool) -> Vec<(&'static str, String)> {
    let mut plan: Vec<(&'static str, String)> = Vec::new();

    if which("gaze-omarchy") {
        plan.push((RESTORE_OMARCHY_LOCK_STEP, "gaze-omarchy disable".into()));
    }

    if which("gnome-extensions") {
        plan.push((
            "禁用并卸载 GNOME 扩展（尽可能完成）",
            "gnome-extensions disable gaze@gundulabs.com 2>/dev/null || true; \
              gnome-extensions uninstall gaze@gundulabs.com 2>/dev/null || true"
                .into(),
        ));
    }

    plan.push(("重置 GNOME 锁屏和登录设置", reset_gnome_user_settings_cmd()));
    plan.push((
        "删除各用户的 GNOME 扩展副本",
        "for d in /home/*/.local/share/gnome-shell/extensions /root/.local/share/gnome-shell/extensions; do \
          [ -d \"$d/gaze@gundulabs.com\" ] || continue; \
          sudo rm -rf \"$d/gaze@gundulabs.com\"; \
          done"
            .into(),
    ));
    plan.push((
        "删除安装程序的一次性 GNOME 启用项",
        "for h in /home/* /root; do \
          sudo rm -f \"$h/.config/autostart/gaze-gnome-enable.desktop\" \"$h/.local/share/gaze/gnome-enable.sh\"; \
          done"
            .into(),
    ));
    plan.push(("删除 GDM dconf 覆盖配置", remove_gdm_dconf_overrides_cmd()));

    if which("pam-auth-update") {
        plan.push((
            "删除 Debian/Ubuntu PAM 配置",
            "sudo pam-auth-update --package --remove gaze 2>/dev/null || true".into(),
        ));
    }
    if which("authselect") {
        plan.push(("恢复 authselect 配置", restore_authselect_cmd()));
    }

    if which("pacman") && !which("pam-auth-update") && !which("authselect") {
        plan.push(("删除 Arch PAM 配置", remove_arch_pam_configuration_cmd()));
    }

    plan.push((
        "删除 hyprlock 对 Gaze PAM 的引用",
        "for d in /home/*/.config/hypr /root/.config/hypr; do \
          f=\"$d/hyprlock.conf\"; \
          [ -f \"$f\" ] || continue; \
          sudo sed -i.gaze-uninstall-bak \
            '/^\\s*\\(pam_\\)\\?module\\s*=\\s*hyprlock-gaze\\(-simultaneous\\)\\?\\s*$/d' \"$f\" || true; \
          done"
            .into(),
    ));

    plan.push((
        "停止并禁用守护进程",
        "sudo systemctl disable --now gazed 2>/dev/null || true".into(),
    ));

    if let Some(package_manager) = detect_package_manager() {
        append_package_manager_uninstall_steps(&mut plan, package_manager);
    }

    if which("semodule") {
        plan.push((
            "删除 SELinux 策略",
            "sudo semodule -r gaze-gdm-camera 2>/dev/null; sudo semodule -r gaze-greeter-keyring 2>/dev/null || true".into(),
        ));
    }

    plan.push((
        "删除未受软件包管理的开发链接和文件",
        remove_unmanaged_install_artifacts_cmd(),
    ));

    plan.push((
        // gazed holds decrypted face templates in memory, so its crash dumps
        // are biometric data too.
        "删除 gaze 核心转储",
        "[ -d /var/lib/systemd/coredump ] && \
          sudo find /var/lib/systemd/coredump \\( -name 'core.gazed.*' \
          -o -name 'core.gaze.*' -o -name 'core.gaze-gui.*' \\) -delete \
          2>/dev/null || true"
            .into(),
    ));
    plan.push(("删除模型缓存", "sudo rm -rf /var/cache/gaze".into()));
    plan.push(("删除配置", "sudo rm -rf /etc/gaze".into()));
    if !keep_data {
        plan.push(("删除已录入的人脸数据", "sudo rm -rf /var/lib/gaze".into()));
    }

    plan.push(("刷新 GNOME 系统设置", refresh_gnome_system_settings_cmd()));
    plan.push(("重新加载 systemd", "sudo systemctl daemon-reload".into()));

    plan
}

fn handle_uninstall(yes: bool, keep_data: bool, dry_run: bool) -> anyhow::Result<()> {
    let term = Term::stdout();
    let plan = build_uninstall_plan(keep_data);

    term.write_line(&format!("\n{}\n", style("Gaze 卸载计划").red().bold()))?;
    for (i, (desc, cmd)) in plan.iter().enumerate() {
        term.write_line(&format!(
            "  {} {}\n    {}",
            style(format!("{:>2}.", i + 1)).dim(),
            style(desc).bold(),
            style(cmd).dim()
        ))?;
    }
    term.write_line("")?;

    if keep_data {
        term.write_line(&format!(
            "  {} 将保留 /var/lib/gaze（已录入的人脸）。",
            style("i").cyan().bold()
        ))?;
    } else {
        term.write_line(&format!(
            "  {} 这将删除已录入的人脸数据。使用 --keep-data 可保留数据。",
            style("!").yellow().bold()
        ))?;
    }
    term.write_line("")?;

    if dry_run {
        term.write_line(&format!(
            "{} 试运行；未执行任何命令。",
            style("i").cyan().bold()
        ))?;
        return Ok(());
    }

    if !yes {
        let theme = ColorfulTheme::default();
        let proceed = Select::with_theme(&theme)
            .with_prompt("继续卸载？")
            .items(["否，取消", "是，卸载 Gaze"])
            .default(0)
            .interact()?;
        if proceed != 1 {
            term.write_line(&format!("{} 已取消。", style("✗").red().bold()))?;
            return Ok(());
        }
    }

    for (desc, cmd) in &plan {
        term.write_line(&format!("\n{} {}", style("▶").cyan().bold(), desc))?;
        let status = std::process::Command::new("sh").arg("-c").arg(cmd).status();
        match status {
            Ok(s) if s.success() => {
                term.write_line(&format!("  {} 完成", style("✓").green()))?;
            }
            Ok(s) => {
                if *desc == RESTORE_OMARCHY_LOCK_STEP {
                    anyhow::bail!(
                        "恢复 Omarchy 锁屏失败；尚未删除 Gaze。请先在已解锁的桌面中运行 gaze-omarchy disable。"
                    );
                }
                term.write_line(&format!(
                    "  {} 步骤以 {} 退出（继续）",
                    style("!").yellow(),
                    s.code().unwrap_or(-1)
                ))?;
            }
            Err(e) => {
                if *desc == RESTORE_OMARCHY_LOCK_STEP {
                    anyhow::bail!("无法恢复 Omarchy 锁屏：{e}。尚未删除 Gaze。");
                }
                term.write_line(&format!(
                    "  {} 无法启动：{}（继续）",
                    style("!").yellow(),
                    e
                ))?;
            }
        }
    }

    term.write_line(&format!(
        "\n{} Gaze 已卸载。建议重启以清除内存中的状态。",
        style("✓").green().bold()
    ))?;
    term.write_line(&format!(
        "  {} 如果 hyprlock.conf 引用了 Gaze，则已在其旁边保存备份 hyprlock.conf.gaze-uninstall-bak。",
        style("i").cyan().bold()
    ))?;
    Ok(())
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("错误：{error:#}");
        std::process::exit(1);
    }
}

fn run_main() -> anyhow::Result<()> {
    CompleteEnv::with_factory(Cli::command).complete();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let cli = parse_cli();

    if let Some(name) = command_requires_root(&cli.command)
        && !is_root()
    {
        reexec_as_root(name)?;
    }

    let silent_auth = matches!(cli.command, Commands::Auth { silent: true, .. });

    let _polkit_agent =
        (command_may_be_challenged(&cli.command) && !silent_auth).then(polkit::PolkitAgent::spawn);

    match &cli.command {
        Commands::Keyring {
            forget,
            user,
            kwallet,
        } => {
            let backend = if *kwallet {
                gaze_security::keyring::Backend::KWallet
            } else {
                gaze_security::keyring::Backend::Gnome
            };
            let username = user.clone().unwrap_or_else(get_current_user);
            if *forget {
                gaze_security::keyring::forget_for(backend, &username)?;
                println!("已删除 {username} 已存储的 {} 凭据。", backend.name());
            } else {
                keyring::enroll(&username, &Config::load()?, backend)?;
            }
            return Ok(());
        }
        Commands::Uninstall {
            yes,
            keep_data,
            dry_run,
        } => return handle_uninstall(*yes, *keep_data, *dry_run),
        Commands::Doctor { user, benchmark } => {
            let username = user.clone().unwrap_or_else(get_current_user);
            let healthy = doctor::run(&username, *benchmark).await?;
            if !healthy {
                std::process::exit(1);
            }
            return Ok(());
        }
        _ => {}
    }

    let proxy = match connect_gaze().await {
        Ok(proxy) => proxy,
        Err(_) if silent_auth => std::process::exit(1),
        Err(e) => return Err(e.into()),
    };

    match cli.command {
        Commands::Auth {
            user,
            verbose,
            silent,
        } => {
            let result = handle_auth(
                &proxy,
                &user.unwrap_or_else(get_current_user),
                verbose,
                silent,
            )
            .await;
            if silent && result.is_err() {
                std::process::exit(1);
            }
            result?;
        }
        Commands::AddFace { user, face } => {
            handle_enroll(&proxy, &user.unwrap_or_else(get_current_user), &face, false).await?;
        }
        Commands::RefineFace { user, face } => {
            handle_enroll(&proxy, &user.unwrap_or_else(get_current_user), &face, true).await?;
        }
        Commands::ListFaces { user } => {
            handle_list_faces(&proxy, &user.unwrap_or_else(get_current_user)).await?;
        }
        Commands::RemoveFace { user, face } => {
            handle_remove_face(&proxy, &user.unwrap_or_else(get_current_user), &face).await?;
        }
        Commands::RenameFace { user, from, to } => {
            handle_rename_face(&proxy, &user.unwrap_or_else(get_current_user), &from, &to).await?;
        }
        Commands::ClearUser { user } => {
            handle_clear_user(&proxy, &user.unwrap_or_else(get_current_user)).await?;
        }
        Commands::Duress { clear, user } => {
            handle_duress(&proxy, &user.unwrap_or_else(get_current_user), clear).await?;
        }
        Commands::Config { show } => {
            let (config, keyring_supported) = load_config_with_keyring_from_daemon(&proxy).await?;
            if show {
                println!(
                    "{} {}",
                    style("inference.execution_provider:").bold(),
                    config.inference.execution_provider
                );
                println!(
                    "{} {}",
                    style("inference.device:").bold(),
                    config.inference.device
                );
                let level_name = config.security.level.as_str();
                println!("{} {}", style("security.level:").bold(), level_name);
                println!(
                    "{} {}",
                    style("security.detector:").bold(),
                    config.security.detector()
                );
                println!(
                    "{} {}",
                    style("security.recognizer:").bold(),
                    config.security.recognizer()
                );
                println!(
                    "{} {:.2}",
                    style("security.rgb_threshold:").bold(),
                    config.security.rgb_threshold()
                );
                println!(
                    "{} {:.2}",
                    style("security.ir_threshold:").bold(),
                    config.security.ir_threshold()
                );
                println!(
                    "{} {}",
                    style("security.hybrid_policy:").bold(),
                    if config.security.hybrid_policy.is_empty() {
                        format!("\"\"（解析为：{}）", config.security.hybrid_policy())
                    } else {
                        config.security.hybrid_policy.clone()
                    }
                );
                println!("{} {}", style("cameras.rgb:").bold(), config.cameras.rgb);
                println!("{} {}", style("cameras.ir:").bold(), config.cameras.ir);
                println!(
                    "{} {}",
                    style("cameras.emitter_enabled:").bold(),
                    config.cameras.emitter_enabled
                );
                println!(
                    "{} {}",
                    style("cameras.dark_luma_threshold:").bold(),
                    config.cameras.dark_luma_threshold
                );
                println!(
                    "{} {}",
                    style("cameras.parallel_capture:").bold(),
                    config.cameras.parallel_capture()
                );
                println!(
                    "{} {}",
                    style("auth.abort_if_ssh:").bold(),
                    config.auth.abort_if_ssh
                );
                println!(
                    "{} {}",
                    style("auth.abort_if_lid_closed:").bold(),
                    config.auth.abort_if_lid_closed
                );
                println!(
                    "{} {}",
                    style("auth.abort_before_first_resume:").bold(),
                    config.auth.abort_before_first_resume
                );
                println!(
                    "{} {}",
                    style("auth.require_confirmation_lock_screen:").bold(),
                    config.auth.require_confirmation_lock_screen
                );
                println!(
                    "{} {}",
                    style("auth.require_confirmation_elevation:").bold(),
                    config.auth.require_confirmation_elevation
                );
                println!(
                    "{} {}",
                    style("auth.resume_grace_ms:").bold(),
                    config.auth.resume_grace_ms
                );
                println!(
                    "{} {}",
                    style("auth.start_delay_ms:").bold(),
                    config.auth.start_delay_ms
                );
                println!(
                    "{} {}",
                    style("auth.start_delay_scope:").bold(),
                    config.auth.start_delay_scope()
                );

                println!(
                    "{} {}",
                    style("enrollment.max_templates:").bold(),
                    config.enrollment.max_templates
                );
                println!(
                    "{} {:.2}",
                    style("enrollment.min_face_size_ratio:").bold(),
                    config.enrollment.min_face_size_ratio
                );
                println!(
                    "{} {}",
                    style("liveness.enabled:").bold(),
                    config.liveness.enabled
                );
                println!(
                    "{} {:.2}",
                    style("liveness.threshold:").bold(),
                    config.liveness.threshold
                );
                println!(
                    "{} {:.1}秒",
                    style("liveness.max_seconds:").bold(),
                    config.liveness.max_seconds
                );
                println!(
                    "{} {}",
                    style("storage.encrypt_templates:").bold(),
                    config.storage.encrypt_templates
                );
                println!(
                    "{} {}",
                    style("storage.unlock_gnome_keyring:").bold(),
                    config.storage.unlock_gnome_keyring
                );
                println!(
                    "{} {}",
                    style("storage.unlock_kwallet:").bold(),
                    config.storage.unlock_kwallet
                );
                return Ok(());
            }
            run_config_wizard(&Term::stdout(), &proxy, config, keyring_supported).await?;
        }

        Commands::Doctor { .. } | Commands::Uninstall { .. } | Commands::Keyring { .. } => {
            unreachable!("handled before DBus connection")
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_has(plan: &[(&'static str, String)], label: &str) -> bool {
        plan.iter().any(|(candidate, _)| *candidate == label)
    }

    #[test]
    fn an_unconfigured_spectrum_reads_as_unlit_not_as_a_failure() {
        assert_eq!(spectrum_badge_state(true, true), SpectrumBadge::Enrolled);
        assert_eq!(
            spectrum_badge_state(true, false),
            SpectrumBadge::Enrolled,
            "captures already taken stay green even after the camera is unset"
        );
        assert_eq!(
            spectrum_badge_state(false, true),
            SpectrumBadge::Missing,
            "a configured camera the profile never captured is a real gap"
        );
        assert_eq!(
            spectrum_badge_state(false, false),
            SpectrumBadge::Unused,
            "an RGB-only machine has nothing to enroll for IR, so IR is not a failure"
        );
        assert!(spectrum_badge("RGB", true, true).contains("[RGB]"));
    }

    #[test]
    fn cli_parses_auth_and_safe_uninstall_flags() {
        let cli = Cli::try_parse_from(["gaze", "auth", "--user", "alice", "--verbose"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Auth {
                user: Some(ref user),
                verbose: true,
                silent: false,
            } if user == "alice"
        ));

        let cli = Cli::try_parse_from(["gaze", "auth", "-s", "-u", "bob"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Auth {
                user: Some(ref user),
                verbose: false,
                silent: true,
            } if user == "bob"
        ));

        let cli = Cli::try_parse_from(["gaze", "auth", "--silent"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Auth {
                user: None,
                verbose: false,
                silent: true,
            }
        ));

        assert!(Cli::try_parse_from(["gaze", "auth", "--verbose", "--silent"]).is_err());

        let cli = Cli::try_parse_from(["gaze", "uninstall", "--yes", "--keep-data", "--dry-run"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Uninstall {
                yes: true,
                keep_data: true,
                dry_run: true
            }
        ));

        let cli = Cli::try_parse_from(["gaze", "doctor", "--user", "alice"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Doctor {
                user: Some(ref user),
                benchmark: false,
            } if user == "alice"
        ));

        let cli = Cli::try_parse_from(["gaze", "doctor", "--benchmark"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Doctor {
                benchmark: true,
                ..
            }
        ));
    }

    #[test]
    fn face_and_config_writes_require_root() {
        for (args, expected) in [
            (vec!["gaze", "add-face", "default"], "add-face"),
            (vec!["gaze", "refine-face", "default"], "refine-face"),
            (vec!["gaze", "remove-face", "default"], "remove-face"),
            (vec!["gaze", "rename-face", "old", "new"], "rename-face"),
            (vec!["gaze", "clear-user"], "clear-user"),
            (vec!["gaze", "config"], "config"),
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            assert_eq!(
                command_requires_root(&cli.command),
                Some(expected),
                "{args:?} must require root"
            );
        }
    }

    #[test]
    fn forgetting_a_keyring_credential_requires_root() {
        let cli = Cli::try_parse_from(["gaze", "keyring", "--forget"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Keyring { forget: true, .. }
        ));
        assert_eq!(command_requires_root(&cli.command), Some("keyring"));
    }

    #[test]
    fn read_only_commands_stay_unprivileged() {
        for args in [
            vec!["gaze", "auth"],
            vec!["gaze", "list-faces"],
            vec!["gaze", "doctor"],
            vec!["gaze", "config", "--show"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            assert_eq!(
                command_requires_root(&cli.command),
                None,
                "{args:?} must stay unprivileged"
            );
        }
    }

    #[test]
    fn only_cross_user_reads_need_a_tty_polkit_agent() {
        let cli = Cli::try_parse_from(["gaze", "list-faces", "--user", "alice"]).unwrap();
        assert_eq!(command_target_user(&cli.command), Some("alice"));

        let cli = Cli::try_parse_from(["gaze", "doctor", "--user", "alice"]).unwrap();
        assert_eq!(command_target_user(&cli.command), Some("alice"));

        let cli = Cli::try_parse_from(["gaze", "auth"]).unwrap();
        assert_eq!(command_target_user(&cli.command), None);

        let cli = Cli::try_parse_from(["gaze", "add-face", "default"]).unwrap();
        assert_eq!(command_target_user(&cli.command), None);
    }

    #[test]
    fn clearing_a_duress_lockout_always_needs_a_tty_polkit_agent() {
        let clear = Cli::try_parse_from(["gaze", "duress", "--clear"]).unwrap();
        assert!(command_may_be_challenged_as(&clear.command, false, "alice"));
        assert!(!command_may_be_challenged_as(&clear.command, true, "alice"));

        let own = Cli::try_parse_from(["gaze", "duress", "--clear", "--user", "alice"]).unwrap();
        assert!(command_may_be_challenged_as(&own.command, false, "alice"));

        let show = Cli::try_parse_from(["gaze", "duress"]).unwrap();
        assert!(!command_may_be_challenged_as(&show.command, false, "alice"));

        let other = Cli::try_parse_from(["gaze", "duress", "--user", "bob"]).unwrap();
        assert!(command_may_be_challenged_as(&other.command, false, "alice"));
    }

    #[test]
    fn resolve_current_user_prefers_the_account_behind_sudo() {
        assert_eq!(
            resolve_current_user(Some("alice".into()), Some("root".into())),
            "alice"
        );
        assert_eq!(resolve_current_user(None, Some("alice".into())), "alice");
        assert_eq!(
            resolve_current_user(Some(String::new()), Some("alice".into())),
            "alice"
        );
        assert_eq!(resolve_current_user(None, None), "root");
    }

    #[test]
    fn uninstall_plan_preserves_face_data_only_when_requested() {
        assert!(plan_has(
            &build_uninstall_plan(false),
            "删除已录入的人脸数据"
        ));
        assert!(!plan_has(
            &build_uninstall_plan(true),
            "删除已录入的人脸数据"
        ));
    }

    #[test]
    fn uninstall_always_removes_unmanaged_development_artifacts() {
        let plan = build_uninstall_plan(true);
        assert!(plan_has(&plan, "删除未受软件包管理的开发链接和文件"));

        let command = remove_unmanaged_install_artifacts_cmd();
        for path in [
            "/usr/bin/gaze",
            "/usr/local/bin/gazed",
            "/usr/lib/security/pam_gaze.so",
            "/usr/share/gnome-shell/extensions/gaze@gundulabs.com/extension.js",
            "/usr/share/polkit-1/actions/com.gundulabs.gaze.policy",
            "/usr/local/share/gaze-dev",
        ] {
            assert!(command.contains(path), "missing cleanup for {path}");
        }
        assert!(command.contains("[ -L \"$p\" ] || ! owned_by_pkg \"$p\""));
        assert!(command.contains("sudo rm -rf /etc/systemd/system/gazed.service.d"));
    }

    #[test]
    fn uninstall_plan_removes_per_user_extensions_and_core_dumps() {
        let plan = build_uninstall_plan(true);
        assert!(plan_has(&plan, "删除各用户的 GNOME 扩展副本"));
        assert!(plan_has(&plan, "删除 gaze 核心转储"));

        let (_, cmd) = plan
            .iter()
            .find(|(desc, _)| *desc == "删除各用户的 GNOME 扩展副本")
            .unwrap();
        assert!(cmd.contains("/home/*/.local/share/gnome-shell/extensions"));
        assert!(cmd.contains("/root/.local/share/gnome-shell/extensions"));

        let (_, cmd) = plan
            .iter()
            .find(|(desc, _)| *desc == "删除 gaze 核心转储")
            .unwrap();
        assert!(cmd.contains("/var/lib/systemd/coredump"));
    }

    #[test]
    fn omarchy_plugin_version_matches_release() {
        let manifest = include_str!("../../../integrations/omarchy/manifest.json");
        let expected = format!("\"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
        assert!(
            manifest.contains(&expected),
            "integrations/omarchy/manifest.json must carry version {}",
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn pacman_removal_covers_debug_split_packages() {
        let command = remove_pacman_packages_cmd();
        assert!(command.contains("gaze-bin"));
        assert!(command.starts_with("for base in gaze-omarchy-bin gaze-omarchy gaze "));
        assert!(command.contains("\"$base-debug\" \"$base\""));

        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "invalid pacman removal shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn zypper_removal_covers_all_native_packages() {
        let command = remove_zypper_packages_cmd();
        for package in [
            "gaze",
            "gaze-gui",
            "gaze-gnome-extension",
            "gaze-hyprlock",
            "gaze-kde",
            "gaze-omarchy",
        ] {
            assert!(
                command.contains(package),
                "missing zypper removal for {package}"
            );
        }
        assert!(command.contains("zypper --non-interactive remove --no-confirm"));

        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "invalid zypper removal shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn suse_uninstall_removes_both_pam_config_definitions() {
        let command = remove_suse_pam_configuration_cmd();
        assert!(command.contains("pam-config --delete --gaze"));
        assert!(command.contains("pam-config --delete --gaze_grosshack"));
        assert!(command.contains("pam-config --update"));

        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "invalid openSUSE PAM cleanup shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn suse_uninstall_branch_removes_packages_pam_repo_and_imported_key() {
        let mut plan = Vec::new();
        append_package_manager_uninstall_steps(&mut plan, PackageManager::Zypper);

        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].0, "删除 openSUSE PAM 配置");
        assert_eq!(plan[1].0, "删除 zypper 软件包");
        assert_eq!(plan[2].0, "删除 zypper 软件源和密钥");

        let command = &plan[2].1;
        assert!(command.contains("/etc/zypp/repos.d/gundulabs.repo"));
        assert!(command.contains("/etc/pki/rpm-gpg/RPM-GPG-KEY-gundulabs"));
        assert!(command.contains("gpg-pubkey-5c1c7c98-*)"));
        assert!(command.contains("sudo rpm -e \"$key_package\""));
        assert_eq!(
            GUNDULABS_REPO_KEY_FINGERPRINT,
            "505AC1C71AFEDBD5555235F6CB4FA24E5C1C7C98"
        );
        assert!(!command.contains("rpm -e gpg-pubkey*"));

        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(command)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "invalid openSUSE repo/key cleanup shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn open_suse_package_manager_precedes_dnf_when_both_are_available() {
        assert_eq!(
            package_manager_from_availability(false, true, true, false, false),
            Some(PackageManager::Zypper)
        );
        assert_eq!(
            package_manager_from_availability(true, true, true, false, false),
            Some(PackageManager::Zypper)
        );
    }

    #[test]
    fn rpm_ostree_package_manager_precedes_dnf_when_both_are_available() {
        assert_eq!(
            package_manager_from_availability(false, false, true, false, true),
            Some(PackageManager::RpmOstree)
        );
        assert_eq!(
            package_manager_from_availability(false, false, true, false, false),
            Some(PackageManager::Dnf)
        );
    }

    #[test]
    fn rpm_ostree_package_cleanup_is_valid_shell() {
        let command = remove_rpm_ostree_packages_cmd();
        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&command)
            .output()
            .expect("failed to run sh -n");
        assert!(
            output.status.success(),
            "invalid rpm-ostree cleanup shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn unmanaged_development_artifact_cleanup_is_valid_shell() {
        let command = remove_unmanaged_install_artifacts_cmd();
        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "invalid cleanup shell command: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn arch_pam_cleanup_handles_package_and_dev_link_markers() {
        let command = remove_arch_pam_configuration_cmd();
        assert!(command.contains("/etc/gaze/pam-arch.configured"));
        assert!(command.contains("/etc/gaze/pam-arch.dev-configured"));
        assert!(command.contains("sed -i '/pam_gaze/d'"));
        assert!(command.contains("/etc/pam.d/sudo"));
        assert!(command.contains("/etc/gaze/pam-arch.polkit-configured"));
        assert!(command.contains("/etc/gaze/pam-arch.polkit-dev-configured"));
        assert!(command.contains("rm -f"));
    }

    fn is_valid_shell(command: &str) -> Result<(), String> {
        let output = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(command)
            .output()
            .map_err(|e| e.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    #[test]
    fn every_capture_status_maps_to_a_tone() {
        // `Ready` stays green through a brief dark dip; `Usable` is ready for matching.
        assert!(matches!(capture_tone(CaptureStatus::Ready), Tone::Good));
        assert!(matches!(capture_tone(CaptureStatus::Usable), Tone::Good));

        // Use red when the scan has nothing it can work with.
        assert!(matches!(capture_tone(CaptureStatus::Unused), Tone::Error));
        assert!(matches!(capture_tone(CaptureStatus::NoFace), Tone::Error));

        // Amber for something the user can correct by moving or turning a light on.
        for status in [
            CaptureStatus::TooDark,
            CaptureStatus::Clipped,
            CaptureStatus::NotCentered,
            CaptureStatus::TooFar,
            CaptureStatus::TooClose,
        ] {
            assert!(
                matches!(capture_tone(status), Tone::Warn),
                "{status:?} is a recoverable framing problem"
            );
        }
    }

    #[test]
    fn a_configured_camera_that_is_not_enumerated_is_still_offered() {
        let mut options = vec![("Built-in".to_string(), "/dev/video0".to_string())];

        ensure_configured_source_listed(&mut options, "/dev/video9");

        assert_eq!(options.len(), 2);
        assert_eq!(
            options[1],
            (
                "/dev/video9（已配置）".to_string(),
                "/dev/video9".to_string()
            ),
            "a camera that is unplugged right now must not silently change"
        );
    }

    #[test]
    fn an_enumerated_camera_is_not_listed_twice() {
        let mut options = vec![("Built-in".to_string(), "/dev/video0".to_string())];

        ensure_configured_source_listed(&mut options, "/dev/video0");
        ensure_configured_source_listed(&mut options, "  /dev/video0  ");

        assert_eq!(options.len(), 1);
    }

    #[test]
    fn an_unset_camera_adds_no_option() {
        let mut options = vec![("Built-in".to_string(), "/dev/video0".to_string())];

        ensure_configured_source_listed(&mut options, "");
        ensure_configured_source_listed(&mut options, "   ");

        assert_eq!(options.len(), 1);
    }

    #[test]
    fn resolve_current_user_ignores_empty_environment_values() {
        assert_eq!(
            resolve_current_user(Some(String::new()), Some("alice".into())),
            "alice",
            "an empty SUDO_USER must not win over USER"
        );
        assert_eq!(
            resolve_current_user(Some(String::new()), Some(String::new())),
            "root"
        );
        assert_eq!(resolve_current_user(None, None), "root");
        assert_eq!(resolve_current_user(None, Some("bob".into())), "bob");
    }

    #[test]
    fn showing_the_config_stays_unprivileged_while_editing_it_does_not() {
        assert_eq!(
            command_requires_root(&Commands::Config { show: true }),
            None,
            "reading the config is not a privileged operation"
        );
        assert_eq!(
            command_requires_root(&Commands::Config { show: false }),
            Some("config")
        );
    }

    #[test]
    fn only_the_commands_that_name_a_user_have_a_target() {
        assert_eq!(
            command_target_user(&Commands::Auth {
                user: Some("alice".into()),
                verbose: false,
                silent: false,
            }),
            Some("alice")
        );
        assert_eq!(
            command_target_user(&Commands::ListFaces {
                user: Some("bob".into())
            }),
            Some("bob")
        );
        assert_eq!(
            command_target_user(&Commands::Auth {
                user: None,
                verbose: false,
                silent: false,
            }),
            None
        );
        assert_eq!(
            command_target_user(&Commands::Config { show: true }),
            None,
            "config is never run against another account"
        );
    }

    #[test]
    fn which_finds_a_real_binary_and_not_an_invented_one() {
        assert!(which("sh"), "sh must exist wherever the uninstaller runs");
        assert!(!which("gaze-definitely-not-a-real-binary"));
    }

    #[test]
    fn the_escalation_marker_is_passed_through_to_the_re_executed_process() {
        assert_eq!(ESCALATION_MARKER, "GAZE_ESCALATED");
        assert!(
            ESCALATION_PRESERVED_ENV.contains(&"XDG_RUNTIME_DIR"),
            "the session bus address is derived from XDG_RUNTIME_DIR, so sudo must keep it"
        );
    }

    #[test]
    fn re_execution_refuses_to_loop_when_it_is_already_escalated() {
        if std::env::var_os(ESCALATION_MARKER).is_none() {
            return;
        }
        let err = reexec_as_root("add-face").expect_err("a second escalation would loop forever");
        assert!(err.to_string().contains("未获得 root 权限"));
    }

    #[test]
    fn the_gnome_cleanup_commands_are_valid_shell() {
        for (label, command) in [
            ("gnome user settings", reset_gnome_user_settings_cmd()),
            ("gdm dconf overrides", remove_gdm_dconf_overrides_cmd()),
            ("gnome system settings", refresh_gnome_system_settings_cmd()),
        ] {
            is_valid_shell(&command).unwrap_or_else(|e| panic!("invalid {label} command: {e}"));
        }
    }

    #[test]
    fn the_distro_cleanup_commands_are_valid_shell() {
        for (label, command) in [
            ("authselect restore", restore_authselect_cmd()),
            ("arch pam", remove_arch_pam_configuration_cmd()),
            ("pacman packages", remove_pacman_packages_cmd()),
            ("zypper packages", remove_zypper_packages_cmd()),
            ("suse pam", remove_suse_pam_configuration_cmd()),
            ("zypper repo and key", remove_zypper_repo_and_key_cmd()),
        ] {
            is_valid_shell(&command).unwrap_or_else(|e| panic!("invalid {label} command: {e}"));
        }
    }

    #[test]
    fn every_uninstall_step_is_valid_shell() {
        for keep_data in [true, false] {
            for (label, command) in build_uninstall_plan(keep_data) {
                is_valid_shell(&command).unwrap_or_else(|e| {
                    panic!("invalid step {label:?} (keep_data={keep_data}): {e}")
                });
            }
        }
    }

    #[test]
    fn the_uninstall_plan_has_no_duplicate_or_unlabelled_steps() {
        let plan = build_uninstall_plan(false);
        assert!(!plan.is_empty());

        let mut labels: Vec<&str> = plan.iter().map(|(label, _)| *label).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len(), "the plan repeats a step label");

        for (label, command) in &plan {
            assert!(
                !label.is_empty(),
                "every step needs a label to show the user"
            );
            assert!(
                !command.trim().is_empty(),
                "step {label:?} has nothing to run"
            );
        }
    }

    #[test]
    fn the_gnome_extension_uuid_is_spelled_the_same_way_everywhere() {
        for command in [
            reset_gnome_user_settings_cmd(),
            remove_unmanaged_install_artifacts_cmd(),
        ] {
            assert!(
                command.contains("gaze@gundulabs.com"),
                "the shell cleanup must target the packaged extension uuid: {command}"
            );
        }
    }
}
