# TimeLockService 🔒

A Windows background service I built to help myself stop wasting time on the internet. It runs as SYSTEM, locks outbound traffic outside work hours, and filters DNS so only whitelisted domains can resolve — even when the firewall is open.

I made a non-admin account for daily use so I can't just stop the service on a whim. That's the whole point.

---

## What it does

- **Work hours (8:45 AM – 5:00 PM, weekdays):** Full internet access. No restrictions.
- **Evening hours (5:00 PM – 11:00 PM, weekdays):** Firewall opens, but DNS goes strict — only work tools and Quran/Islamic sites resolve. Nothing else.
- **Late night + Weekends (Fri/Sat):** Full firewall block. Almost nothing gets through.

DNS is handled by a local whitelist resolver running on port 53. Anything not on the list gets `0.0.0.0` back. The firewall rules are enforced via PowerShell and run as a SYSTEM service so a standard user can't remove them.

---

## Features

- 🕐 **Schedule-based modes** — Work / Evening / Locked, auto-switching every minute
- 🚨 **Tamper detection** — checks every 5 minutes if firewall rules were deleted, re-applies them immediately if so
- 📊 **Daily summary** — logs how many DNS queries were allowed vs blocked each day, with block rate %
- 🔑 **Password-protected whitelist editing** — you can add/remove domains at runtime via a SHA256-hashed password, no service restart needed
- 🗑️ **Daily log rotation** — logs clear once per day, keeping the last 50 lines for context
- 🕌 **Islamic sites always allowed** — Quran, hadith, prayer times, and recitation sites are whitelisted in every mode

---

## Project structure

```
TimeLockService/
├── Worker.cs                  # Main loop, mode switching, tamper detection
├── DnsWhitelistService.cs     # DNS server, strict/full whitelist logic, daily summary
├── WhitelistRequestResolver.cs# Resolves or blocks DNS queries
├── ServiceLogger.cs           # Thread-safe logging + daily rotation
└── Program.cs                 # Host setup, registers both background services
```

---

## Setup

> Requires Windows, .NET 8+, and admin rights to install the service.

**1. Build and publish**
```bash
dotnet publish -c Release -r win-x64 --self-contained
```

**2. Install as a Windows Service**
```powershell
sc create TimeLockService binPath= "C:\TimeLockService\TimeLockService.exe" start= auto
sc failure TimeLockService reset= 0 actions= restart/5000/restart/5000/restart/5000
sc start TimeLockService
```

**3. Set your DNS to localhost**

In your network adapter settings, set DNS to `127.0.0.1`. The service intercepts all DNS queries and forwards only whitelisted ones to Cloudflare (`1.1.1.1`).

**4. Change the password hash**

In `DnsWhitelistService.cs`, replace `PasswordHash` with your own SHA256 hash:
```bash
# Linux/Mac
echo -n "YourPasswordHere" | sha256sum

# PowerShell
[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("YourPasswordHere"))).Replace("-","").ToLower()
```

---

## Adding domains at runtime

You don't need to edit the source or restart the service. Use the static methods exposed on `DnsWhitelistService`:

```csharp
// Add a domain temporarily (survives until service restart)
DnsWhitelistService.TryAddDomain("YourPassword", "example.com");

// Remove a domain
DnsWhitelistService.TryRemoveDomain("YourPassword", "example.com");
```

Wrong password attempts are logged.

---

## Logs

Logs are written to `C:\TimeLockService\`:

| File | Contents |
|---|---|
| `worker.log` | Mode switches, tamper checks, firewall rule status |
| `dns.log` | Every DNS query (allowed/blocked), daily summary |

Both files rotate daily, keeping the last 50 lines so you never lose the midnight summary.

---

## Why I built this

I wanted something that I genuinely couldn't bypass in a moment of weakness — not just a browser extension I could disable, not a hosts file I could edit. A Windows service running as SYSTEM with a non-admin daily account is hard enough to stop that it actually works as a commitment device.

The Islamic sites whitelist is personal. I wanted to make sure Quran and dhikr apps always work regardless of what mode I'm in.

---

## Dependencies

- [DNS.NET](https://github.com/kapetan/dns) — DNS server and client library
- .NET 8 Worker Service
- Windows Firewall (via PowerShell `NetFirewallRule` cmdlets)

---

## License

MIT. Use it however you want. If it helps you, alhamdulillah.
