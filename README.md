## Security Risks of Termux Services

### The `termux-services` package specifically

`termux-services` (which provides `svcad`) is a lightweight init system that keeps processes alive. Its security surface is minimal — it just respawns processes — but it **amplifies** the risks of whatever it's running:

| Risk | Explanation |
|------|-------------|
| **Persistence** | A compromised service (e.g., a malicious HTTP handler) survives reboots if autostarted via `svcad enable`. Without it, a reboot kills it. |
| **No resource limits** | `svcad` has no cgroups, no memory caps, no CPU quotas. A runaway service can OOM-kill the entire phone. |
| **No isolation** | All services run as the same UID (`u0_a399` for Termux). There's no namespace or capability separation between services. A bug in one service can read another service's files. |
| **No audit logging** | `svcad` doesn't log what it starts, when, or what they do. If a service is compromised, you have no forensic trail. |

---

### Services running in Termux (broader risks)

**1. Network exposure**

Any service you bind to `0.0.0.0` (or a LAN IP) is reachable from other devices on your network. On a phone, this is unusual and dangerous:

```bash
# DANGEROUS — reachable from any device on your Wi-Fi:
python -m http.server 8080

# SAFE — loopback only:
python -m http.server 8080 --bind 127.0.0.1
```

If you run `sshd` (via `pkg install openssh`), the risk is higher:
- Android doesn't let non-root apps bind to port 22, so Termux uses port 8022.
- If your phone connects to an untrusted network (café Wi-Fi, hotel), your SSH port is exposed to that network.
- **Mitigation:** key-only auth, disable password auth, use a non-default port, and never expose to the internet without a VPN.

**2. File permission exposure**

The 2022 vulnerability disclosure (CVE in Termux ≤ v0.117) showed that **all files under `/data/data/com.termux/files` were world-readable** — any app on the phone could read your SSH keys, tokens, and service configs. This is fixed in v0.118+, but it illustrates the risk:

- If you're on an old Termux version, **assume all keys are compromised**.
- Even on current versions, files in `~/storage/shared` (the FUSE mount) are readable by any app with `READ_EXTERNAL_STORAGE`. Never store service secrets there.

**3. The `RUN_COMMAND` permission**

Termux declares a custom dangerous-level permission (`com.termux.permission.RUN_COMMAND`) that allows external apps to execute commands in your Termux context. This was the attack vector for:

- **Termux:Tasker privilege escalation** (fixed v0.5, 2020): any app could send `../../../usr/bin/bash` as the executable path.
- **Termux:Widget privilege escalation** (fixed 2022): any app could trigger the shortcut chooser and execute arbitrary commands.

If you have `termux-tasker` or `termux-widget` installed and the `allow-external-apps` property is `true` in `~/.termux/termux.properties`, **any app that holds the `RUN_COMMAND` permission can execute arbitrary commands in your Termux context**. This includes any service you're running.

```bash
# Check your setting:
cat ~/.termux/termux.properties
# If you see: allow-external-apps = true
# And you don't actively use Tasker/Widget automation:
# Set it to false:
sed -i 's/allow-external-apps = true/allow-external-apps = false/' ~/.termux/termux.properties
```

**4. Supply chain (package integrity)**

Services you install via `pkg` come from the Termux repository. The risk model:

- Packages are **cryptographically signed** — a malicious mirror can't serve tampered packages without the signing key.
- However, `termux-change-repo` can select mirrors from anywhere in the world. The signature check protects you, but if the signing key is ever compromised, all mirrors are compromised simultaneously.
- The `ca-certificates` package (Oct 2026 advisory) showed that a compromised CA in the trust store could MITM all HTTPS traffic, including `pkg install` downloads. **Keep `ca-certificates` updated.**

**5. Physical access**

Your phone is portable. If someone has physical access to an unlocked phone:

- They can open Termux and read all service configs, keys, and running processes.
- **Mitigation:** full-disk encryption (default on Android 7+), strong lock screen (8+ digit PIN), SSH key passphrases, and `termux-wake-lock` disabled when not in use.

**6. The 2024 infostealer pattern**

In October 2024, researchers identified an Android infostealer that **abused Termux as its execution environment** — deploying a Python stealer that exfiltrated contacts, SMS, banking data, and WhatsApp files via Telegram. The phone had Termux installed (likely for legitimate use), and the attacker used it as a persistence mechanism.

The lesson: if your phone is compromised at the Android level (malicious app with accessibility permissions, etc.), Termux is a convenient backdoor because it has shell access, network access, and (if you granted storage) access to shared files.

---

### Hardening checklist for your setup

| Action | Priority |
|--------|----------|
| Bind all local services to `127.0.0.1` | Critical |
| Set `allow-external-apps = false` if not using Tasker/Widget | Critical |
| SSH: key-only auth, passphrase-protected Ed25519 keys, non-default port | Critical (if running sshd) |
| `chmod 600` on all key files, `chmod 700` on `~/.ssh` | High |
| Never store secrets in `~/storage/shared` | High |
| Keep Termux updated (`pkg upgrade`) — especially `ca-certificates` | High |
| Use `svcad` only for services you actively need; disable on reboot otherwise | Medium |
| Add a cron disk-space monitor (as you already planned) | Medium |
| Full-disk encryption + strong lock screen | Medium |

---

### What `termux-services` does NOT do (and what that means)

| Missing feature | Risk |
|-----------------|------|
| No cgroups / resource limits | A memory-leaking service can OOM the phone |
| No network namespace isolation | All services share the same network stack; a compromised service can sniff other services' traffic |
| No capability dropping | Services run with full Termux UID capabilities |
| No TLS termination | If you run an HTTP service, it's plaintext unless you add TLS yourself |
| No health checks / restart policies beyond `Restart=on-failure` | A zombie service won't be killed |

