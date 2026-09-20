# Linux Server Hardening Script

A single-file bash script that hardens a fresh Debian/Ubuntu server: dedicated
sudo user, SSH lockdown, UFW firewall with an SSH IP allowlist and custom
port-scan/traffic-logging chains, fail2ban, kernel `sysctl` hardening, IPv6
disable, chrony NTP, and centralized rsyslog/logrotate.

## Compatibility

Debian 11/12/13 and Ubuntu 20.04+ (and derivatives). It depends on `apt`,
`ufw`, and `systemd`, so it will **not** run as-is on RHEL/CentOS/Fedora
(`dnf`, `firewalld`), Alpine (`apk`, no systemd), Arch (`pacman`), or
openSUSE (`zypper`).

## Before you run it

Open `hardening_script.sh` and edit the config block near the top —
**the script refuses to run until every `CHANGE_ME_*` placeholder is
replaced**, since running it unedited would either fail outright or, worse,
firewall you out with no SSH access left:

```bash
NEW_USER="guest"                                 # the admin user it creates
NEW_USER_PASSWORD="CHANGE_ME_STRONG_PASSWORD"    # set a real password
NEW_HOSTNAME="CHANGE_ME_HOSTNAME"                # this server's hostname
ALERT_EMAIL="CHANGE_ME_ALERT_EMAIL"              # fail2ban notification email
NEW_USER_SSH_PUBKEY=""                           # optional: paste a public key to enable key-only SSH login
SSH_ALLOWED_IPS="CHANGE_ME_YOUR_CURRENT_IP"       # your real admin IP(s), space-separated
```

`SSH_ALLOWED_IPS` matters most: only these IPs can reach SSH after the
script runs. Double-check your current IP is in that list before running.

If you leave `NEW_USER_SSH_PUBKEY` empty, SSH password authentication stays
on (weaker, but you won't be locked out without a key ready). If you provide
a key, the script installs it and switches to key-only login automatically.

## Sudo permission: passwordless by default

The script grants `NEW_USER` **passwordless sudo** (`NOPASSWD: ALL`), written
to `/etc/sudoers.d/<NEW_USER>`:

```
guest ALL=(ALL:ALL) ALL
guest ALL=(ALL:ALL) NOPASSWD: ALL
```

This is convenient if you're chaining more automation on top (no password
prompts breaking a scripted sequence), but it does mean anything that runs
as that user — a compromised app, a phished session — can escalate to root
instantly without needing to know any password. If you'd rather require a
password for sudo (more secure, more friction), open the script and find
this block in `step_create_user()`:

```bash
{
    echo "${NEW_USER} ALL=(ALL:ALL) ALL"
    echo "${NEW_USER} ALL=(ALL:ALL) NOPASSWD: ALL"
} > "${sudoers_file}"
```

Delete the `NOPASSWD: ALL` line (keep just the first `echo`) before running
the script, or edit `/etc/sudoers.d/<user>` afterward and remove that line,
then run `visudo -c` to confirm the file is still syntactically valid.

## Usage

```bash
sudo bash hardening_script.sh
```

It will show a 10-second countdown (Ctrl+C to abort), and if it detects your
current SSH source IP isn't in `SSH_ALLOWED_IPS`, it requires typing
`IUNDERSTAND` before proceeding, so you don't lock yourself out by mistake.

After it finishes, **verify SSH access from a new terminal before closing
your current session**, then reboot to apply the IPv6/GRUB and sysctl
changes. The script prints a full post-run checklist at the end.

## What it does

1. Sets timezone, runs `apt update && apt upgrade`
2. Installs diagnostic tools (`nmap`, `tcpdump`, `bind9-dnsutils`, etc.)
3. Creates the admin user + sudo, optionally installs an SSH key
4. Hardens `sshd_config` (no root login, no empty passwords, restricted
   forwarding, `AllowUsers`, custom banner)
5. Sets the hostname
6. Configures rsyslog + logrotate
7. Configures UFW: default-deny incoming/outgoing/forward, an SSH IP
   allowlist, and two custom logging chains (rate-limited port-scan
   detection and rate-limited traffic logging)
8. Disables IPv6 (`sysctl` + GRUB)
9. Applies kernel `sysctl` hardening (ASLR, anti-spoofing, redirects off,
   SYN cookies, etc.)
10. Installs and configures fail2ban (sshd + recidive + a custom
    port-scan jail wired to the UFW logging chain)
11. Configures NTP via chrony
12. Finalizes and rotates its own log

Full run log: `/var/log/hardening_script.log`.

## License

Use at your own risk. Read the script before running it on anything you
care about, especially the firewall and SSH sections.
