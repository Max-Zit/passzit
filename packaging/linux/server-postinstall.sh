#!/bin/sh
set -e
if ! getent passwd passzit >/dev/null; then
    useradd --system --home-dir /var/lib/passzit --shell /usr/sbin/nologin passzit 2>/dev/null \
      || useradd --system --home-dir /var/lib/passzit --shell /sbin/nologin passzit
fi
install -d -m 0700 -o passzit -g passzit /var/lib/passzit
install -d -m 0750 -o passzit -g passzit /var/lib/passzit/helper
install -d -m 0700 -o root -g root /var/cache/passzit
chown root:passzit /etc/passzit/server.env
chmod 640 /etc/passzit/server.env
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable passzit-server.service >/dev/null 2>&1 || true
    systemctl enable --now passzit-helper.path >/dev/null 2>&1 || true
    # An upgrade by hand (dpkg -i, rpm -U) runs the new version right away.
    systemctl try-restart passzit-server.service >/dev/null 2>&1 || true
fi
if grep -q 'CHANGE_ME' /etc/passzit/server.env; then
    echo "PassZit server installed. Set PASSZIT_DB in /etc/passzit/server.env,"
    echo "then: systemctl start passzit-server (or use install.sh, which does all of it)."
fi
# The PassZit appliance (not other servers): the setup menu on its
# screen, the start-up script and hardened SSH.
if [ -f /var/lib/passzit/.appliance ]; then
    a=/usr/share/passzit/appliance
    install -m 0755 $a/passzit-setup /usr/local/sbin/passzit-setup
    install -m 0755 $a/passzit-appliance-boot /usr/local/sbin/passzit-appliance-boot
    install -m 0644 $a/passzit-appliance-boot.service /etc/systemd/system/passzit-appliance-boot.service
    install -m 0644 $a/passzit-menu.sh /etc/profile.d/passzit-menu.sh
    install -m 0440 $a/sudoers-passzit-setup /etc/sudoers.d/passzit-setup
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable passzit-appliance-boot.service >/dev/null 2>&1 || true
    if [ -d /etc/ssh/sshd_config.d ]; then
        install -m 0644 $a/sshd-passzit.conf /etc/ssh/sshd_config.d/50-passzit.conf
        # Inside the installer (no host keys yet) sshd -t fails anyway: take
        # the file out only when it is what makes the check fail.
        if sshd -t 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || true
        else
            mv /etc/ssh/sshd_config.d/50-passzit.conf /etc/ssh/50-passzit.conf.off
            if sshd -t 2>/dev/null; then
                rm -f /etc/ssh/50-passzit.conf.off
            else
                mv /etc/ssh/50-passzit.conf.off /etc/ssh/sshd_config.d/50-passzit.conf
            fi
        fi
    fi
    [ -f /var/lib/passzit/.appliance-ready ] && /usr/local/sbin/passzit-appliance-boot issue >/dev/null 2>&1 || true
fi
