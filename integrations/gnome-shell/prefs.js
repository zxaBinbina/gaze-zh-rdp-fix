// SPDX-FileCopyrightText: 2026 Gundu Labs
// SPDX-License-Identifier: GPL-3.0-or-later

import Adw from 'gi://Adw';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk';

import {ExtensionPreferences} from 'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js';

const GAZE_DBUS_NAME = 'com.gundulabs.Gaze';
const GAZE_OBJECT_PATH = '/com/gundulabs/Gaze';

const MAX_TRIES_KEY = 'max-face-tries';
const FACE_AUTH_KEY = 'enable-face-authentication';
const RETRY_MODE_KEY = 'face-retry-mode';

function callGaze(method, params) {
    const conn = Gio.DBus.system;
    return new Promise((resolve, reject) => {
        conn.call(
            GAZE_DBUS_NAME, GAZE_OBJECT_PATH, GAZE_DBUS_NAME, method, params,
            null, Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, -1, null,
            (_src, res) => {
                try {
                    resolve(conn.call_finish(res));
                } catch (e) {
                    reject(e);
                }
            }
        );
    });
}
export default class GazePreferences extends ExtensionPreferences {
    fillPreferencesWindow(window) {
        const extensionSettings = this.getSettings();

        const behaviorPage = new Adw.PreferencesPage({
            title: '行为',
            icon_name: 'preferences-system-symbolic',
        });

        const behaviorGroup = new Adw.PreferencesGroup({
            title: '人脸认证',
            description:
                '用于解锁此会话的人脸认证。' +
                '这不会影响 GDM 登录界面（见下方）。' +
                '设置保存在当前 dconf 配置中。',
        });

        const faceRow = new Adw.SwitchRow({
            title: '启用人脸认证（锁屏）',
            active: extensionSettings.get_boolean(FACE_AUTH_KEY),
        });

        faceRow.connect('notify::active', row => {
            extensionSettings.set_boolean(FACE_AUTH_KEY, row.active);
        });
        extensionSettings.connect(`changed::${FACE_AUTH_KEY}`, () => {
            faceRow.set_active(extensionSettings.get_boolean(FACE_AUTH_KEY));
        });
        behaviorGroup.add(faceRow);

        const retryModes = ['disabled', 'fixed', 'infinite'];
        const retryModeRow = new Adw.ComboRow({
            title: '人脸重试模式',
            model: Gtk.StringList.new([
                '禁用',
                '固定次数',
                '无限次'
            ]),
        });
        behaviorGroup.add(retryModeRow);

        const triesRow = new Adw.SpinRow({
            title: '人脸尝试次数上限',
            adjustment: new Gtk.Adjustment({
                lower: 2,
                upper: 20,
                step_increment: 1,
                page_increment: 1,
                value: extensionSettings.get_int(MAX_TRIES_KEY),
            }),
        });
        extensionSettings.bind(
            MAX_TRIES_KEY,
            triesRow,
            'value',
            Gio.SettingsBindFlags.DEFAULT
        );
        behaviorGroup.add(triesRow);

        const updateTriesRowSensitivity = (mode) => {
            triesRow.sensitive = (mode === 'fixed');
        };

        const currentMode = extensionSettings.get_string(RETRY_MODE_KEY);
        const initialIndex = retryModes.indexOf(currentMode);
        if (initialIndex !== -1) {
            retryModeRow.selected = initialIndex;
        }
        updateTriesRowSensitivity(currentMode);

        retryModeRow.connect('notify::selected', () => {
            const selectedMode = retryModes[retryModeRow.selected];
            if (selectedMode) {
                extensionSettings.set_string(RETRY_MODE_KEY, selectedMode);
                updateTriesRowSensitivity(selectedMode);
            }
        });

        extensionSettings.connect(`changed::${RETRY_MODE_KEY}`, () => {
            const val = extensionSettings.get_string(RETRY_MODE_KEY);
            const idx = retryModes.indexOf(val);
            if (idx !== -1 && retryModeRow.selected !== idx) {
                retryModeRow.selected = idx;
            }
            updateTriesRowSensitivity(val);
        });

        behaviorPage.add(behaviorGroup);

        const loginGroup = new Adw.PreferencesGroup({
            title: 'GDM 登录界面',
            description:
                '在 GDM 登录界面启用人脸认证。' +
                '需要管理员授权。' +
                '注意：GNOME 钥匙环通常使用密码解锁，' +
                '因此仅通过人脸登录可能会使其保持锁定。',
        });

        const gdmRow = new Adw.SwitchRow({
            title: '在 GDM 登录时启用人脸认证',
            active: false,
            sensitive: false,
        });

        let suppressGdmNotify = false;
        const setGdmRow = active => {
            suppressGdmNotify = true;
            gdmRow.set_active(active);
            suppressGdmNotify = false;
        };

        callGaze('GetGdmFaceAuth', null)
            .then(result => {
                const [enabled] = result.deepUnpack();
                setGdmRow(enabled);
                gdmRow.set_sensitive(true);
            })
            .catch(error => {
                logError(error, '[gaze] Failed to read GDM face auth state');
                gdmRow.set_subtitle('Gaze 守护进程不可用。');
            });

        const notifyGdmFailure = (error, desired) => {
            const accessDenied =
                Gio.DBusError.is_remote_error(error) &&
                Gio.DBusError.get_remote_error(error) ===
                    'org.freedesktop.DBus.Error.AccessDenied';
            let message;
            if (accessDenied) {
                message = desired
                    ? '在 GDM 登录界面启用人脸认证需要管理员授权。'
                    : '在 GDM 登录界面禁用人脸认证需要管理员授权。';
            } else {
                Gio.DBusError.strip_remote_error(error);
                message = `无法更新 GDM 登录人脸认证：${error.message}`;
            }
            gdmRow.set_subtitle(message);
            if (typeof window.add_toast === 'function')
                window.add_toast(new Adw.Toast({title: message}));
        };

        let gdmRequestInFlight = false;
        gdmRow.connect('notify::active', row => {
            if (suppressGdmNotify || gdmRequestInFlight)
                return;
            const desired = row.active;
            gdmRequestInFlight = true;
            row.set_sensitive(false);
            callGaze('SetGdmFaceAuth', new GLib.Variant('(b)', [desired]))
                .then(() => {
                    gdmRequestInFlight = false;
                    gdmRow.set_sensitive(true);
                    if (typeof window.add_toast === 'function') {
                        const message = desired
                            ? '已在 GDM 登录界面启用人脸认证。重启 GDM（或系统）后生效。'
                            : '已在 GDM 登录界面禁用人脸认证。重启 GDM（或系统）后生效。';
                        window.add_toast(new Adw.Toast({title: message}));
                    }
                })
                .catch(error => {
                    logError(error, '[gaze] Failed to update GDM face auth');
                    gdmRequestInFlight = false;
                    setGdmRow(!desired);
                    gdmRow.set_sensitive(true);
                    notifyGdmFailure(error, desired);
                });
        });
        loginGroup.add(gdmRow);

        behaviorPage.add(loginGroup);

        window.add(behaviorPage);
    }
}
