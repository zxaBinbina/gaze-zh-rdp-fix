#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Called after installation and removal, once the vendor drop-in is in its final state.
# Refresh active user managers only; do not edit anyone's home directory.
if [ -d /run/systemd/system ]; then
    for runtime in /run/user/[0-9]*; do
        [ -S "$runtime/bus" ] || continue
        uid=${runtime##*/}
        user=$(getent passwd "$uid" | cut -d: -f1)
        [ -n "$user" ] || continue
        if systemctl --user --machine="$user@.host" daemon-reload; then
            systemctl --user --machine="$user@.host" --no-block try-restart app-org.kde.krdpserver.service || true
        fi
    done
fi
