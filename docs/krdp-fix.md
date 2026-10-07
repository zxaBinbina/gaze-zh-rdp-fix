# Gaze 与 KRDP 合并修复包

本项目现在同时保存 Gaze 的中文 PAM/KRDP 登录修复，以及 KRDP 6.7.5 的远程画面冻结修复。面向当前 Fedora 44 x86_64 主机。

## 两个独立问题

1. **连接约 4 秒后画面冻结**：Windows App Android 会发出 `SUSPEND_FRAME_ACKNOWLEDGEMENT`。原 KRDP 没有处理这个暂停确认请求，两个待确认帧占满发送窗口后停止发图。修复补齐暂停/恢复确认、累计确认和帧编号回绕处理。
2. **客户端光标和点击位置偏移**：服务端坐标与实际光标相差约 1 像素，视频编解码测试没有平移；用户关闭 **Windows App Android 的硬件解码** 后恢复正常。此设置必须在 Android 客户端调整，RPM 无法代替客户端设置。

对照结果：撤回服务端修复、仅关闭客户端硬件解码时，光标正常但画面仍冻结。因此需要同时保留服务端修复和关闭客户端硬件解码。

另外保留了连接关闭时切回正确线程、点击前同步绝对位置、首帧完整刷新、显示边界及图形协议协商修正。临时坐标日志已移除。

## 安装合并包

在项目根目录执行：

```bash
sudo dnf install ./dist/packages/x86_64/gaze-0.3.7-3.zh_rdp.fc44.x86_64.rpm
```

包名仍为 `gaze`，发行号高于之前的 `2.zh_rdp`，可以直接升级。它包含：

- 本项目编译的 `pam_gaze.so`（中文提示、KRDP 登录跳过人脸扫描）。
- 从同版本基础 RPM 校验后保留的 Gaze 守护进程、CLI、其他文件；不是整个 Gaze 工作区的重新编译。
- 私有 KRDP 修复库：`/usr/lib64/gaze-krdp-fix/6.7.5/libKRdp.so.6`。
- 启动包装脚本：`/usr/libexec/gaze-krdp-server`。
- 系统级用户服务配置：`/usr/lib/systemd/user/app-org.kde.krdpserver.service.d/90-gaze-krdp-fix.conf`。
- 修复源码、补丁及说明：`/usr/share/doc/gaze/krdp-fix/`。

安装脚本会刷新已运行的用户服务管理器，并尝试重启当前正在运行的 KRDP，远程连接会短暂断开。若当前会话未自动刷新，在本地终端执行：

```bash
systemctl --user daemon-reload
systemctl --user restart app-org.kde.krdpserver.service
```

软件包保留 `/etc/gaze/config.toml` 等用户配置，绝不把本机当前配置打入 RPM。也不覆盖官方 `/usr/lib64/libKRdp.so.6`。包装脚本只对 `krdp-6.7.5-1.fc44.x86_64` 启用修复；以后升级到其他 KRDP 构建时自动使用官方库，需要重新评估补丁。

此前会话生成的 `~/.config/systemd/user/app-org.kde.krdpserver.service.d/zz-stream-stability.conf` 不会被 RPM 修改；包装脚本会在进程内清除旧 `LD_LIBRARY_PATH` 并选择包内库，因此不再依赖用户目录中的临时修复库。若用户自行设置了另外的 `ExecStart` 覆盖，需自行核对其优先级。

安装后保持 Windows App **硬件解码关闭**，验证持续刷新、指针点击和断开重连。安装不是对登录/远程场景的自动验证。

## 项目文件

| 路径 | 内容 |
| --- | --- |
| `third_party/krdp/krdp-6.7.5.tar.gz` | 上游源码归档，附 SHA256 元数据，无需从 `/tmp` 找回源码 |
| `third_party/krdp/UPSTREAM.json` | 来源、版本、校验值及支持的 Fedora 构建 |
| `third_party/krdp/patches/` | 修复补丁，包含新增的帧确认辅助代码 |
| `third_party/krdp/CMakeLists.txt` | 本项目使用的 KRDP 库构建入口 |
| `third_party/krdp/tests/` | 帧确认回归测试、1920×1080 编解码位置测试 |
| `third_party/krdp/LICENSES/` | 上游许可证 |
| `scripts/build-krdp-fix.py` | 验证源码、应用补丁、构建和运行测试 |
| `scripts/build-combined-rpm.py` | 构建 PAM 并生成合并 RPM |
| `packaging/krdp-fix/` | RPM 启动包装脚本、服务覆盖与生命周期脚本 |

`target/`、`dist/` 为构建产物，不纳入 Git。源码归档、补丁、测试和脚本均保存到上述正常项目路径。

## 重新构建

需要 Fedora 的 Rust、PAM 开发工具，以及 Qt/KDE、FreeRDP、KPipeWire 开发包。推荐依赖：

```bash
sudo dnf install cargo gcc-c++ cmake ninja-build patch rpm-build cpio binutils \
  pkgconf-pkg-config pam-devel tpm2-tss-devel extra-cmake-modules \
  qt6-qtbase-devel qt6-qtbase-private-devel qt6-qtdeclarative-devel \
  qt6-qtwayland-devel kf6-kcoreaddons-devel kf6-kguiaddons-devel \
  kf6-kconfig-devel freerdp-devel libwinpr-devel kpipewire-devel \
  pipewire-devel libdrm-devel mesa-libgbm-devel plasma-wayland-protocols
python3 scripts/build-krdp-fix.py
```

也支持将开发 RPM 解包到一个目录，不必安装到系统：

```bash
python3 scripts/build-krdp-fix.py --deps-root /path/to/unpacked-rpm-root
```

该目录包含 `usr/include` 和协议文件等；运行库仍使用本机系统库。本次构建保存的临时开发头文件位于项目 `target/krdp-deps`，脚本发现它后会自动使用；新机器仍需准备依赖。

用原来已经生成的 Gaze RPM 作为经过校验的基础载荷：

```bash
python3 scripts/build-combined-rpm.py \
  --base-rpm dist/packages/x86_64/gaze-0.3.7-2.zh_rdp.fc44.x86_64.rpm
```

也可以传入官方 `gaze 0.3.7 x86_64` RPM。基础包的版本、架构和所有文件 SHA256 都会验证。脚本重新构建并测试 PAM；默认也重新构建/测试 KRDP。传入 `--reuse-krdp-build` 可复用项目内已通过测试且校验匹配的 KRDP 构建。

## 回退合并包

之前的 PAM 修复包仍位于 `dist/packages/x86_64/`。可通过以下命令回退为仅含 Gaze PAM 修复的版本：

```bash
sudo dnf downgrade ./dist/packages/x86_64/gaze-0.3.7-2.zh_rdp.fc44.x86_64.rpm
```

若存在此前会话遗留的用户级 `zz-stream-stability.conf`，它可能重新加载旧用户目录修复库；完全回退 KRDP 时应将这份文件移出 `.service.d` 目录，再执行用户级 `daemon-reload` 和 `restart`。用户级文件不会由 RPM 擅自删除。
