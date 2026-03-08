namespace TimeLockService;

using System.Diagnostics;

public class Worker : BackgroundService
{
    private string _currentMode = "UNKNOWN";
    private DateTime _lastTamperCheck = DateTime.MinValue;

    // ─── Schedule Configuration ───────────────────────────────────────────────
    // Work hours: full internet (firewall open, DNS normal whitelist)
    private static readonly TimeSpan WorkStart = new(8, 45, 0);
    private static readonly TimeSpan WorkEnd = new(17, 0, 0);

    // Evening window: DNS becomes STRICT (extra domains removed)
    private static readonly TimeSpan EveningStart = new(17, 0, 0);
    private static readonly TimeSpan EveningEnd = new(23, 0, 0);

    // Late night / early morning: Full lock (firewall blocks everything)
    // Weekends: Full lock all day

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Worker("Service started");
        ApplyCorrectMode();

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            ApplyCorrectMode();
            CheckForTampering();
            ServiceLogger.CleanupIfNeeded();
        }
    }

    private void ApplyCorrectMode()
    {
        var now = DateTime.Now;
        var time = now.TimeOfDay;
        bool isWeekend = now.DayOfWeek is DayOfWeek.Friday or DayOfWeek.Saturday;

        string targetMode;

        if (isWeekend)
        {
            targetMode = "LOCKED";
        }
        else if (time >= WorkStart && time <= WorkEnd)
        {
            targetMode = "WORK";
        }
        else if (time >= EveningStart && time < EveningEnd)
        {
            targetMode = "EVENING"; // firewall off, but DNS is strict
        }
        else
        {
            targetMode = "LOCKED"; // late night
        }

        if (_currentMode == targetMode) return;

        ServiceLogger.Worker("═══════════════════════════════");
        ServiceLogger.Worker($"→ SWITCHING TO {targetMode} MODE");
        ServiceLogger.Worker("═══════════════════════════════");

        switch (targetMode)
        {
            case "WORK": EnableWorkMode(); break;
            case "EVENING": EnableEveningMode(); break;
            case "LOCKED": EnableLockMode(); break;
        }

        _currentMode = targetMode;
    }

    // ─── Modes ────────────────────────────────────────────────────────────────

    private void EnableLockMode()
    {
        RunPS("Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");
        ServiceLogger.Worker("Cleaned old rules");

        RunPS("New-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -Direction Outbound -Protocol TCP -Action Block -Profile Any");
        RunPS("New-NetFirewallRule -DisplayName 'TimeLock-Block-UDP' -Direction Outbound -Protocol UDP -Action Block -Profile Any");

        RunPS(@"New-NetFirewallRule -DisplayName 'TimeLock-Allow-VS' -Direction Outbound -Program 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe' -Action Allow -Profile Any");
        RunPS(@"New-NetFirewallRule -DisplayName 'TimeLock-Allow-RDP' -Direction Outbound -Program 'C:\Windows\System32\mstsc.exe' -Action Allow -Profile Any");

        // Signal DNS service to use strict whitelist
        DnsWhitelistService.SetStrictMode(true);

        ServiceLogger.Worker("LOCK MODE ACTIVE — Internet fully blocked");
    }

    private void EnableEveningMode()
    {
        // Remove firewall blocks so normal browsing works
        RunPS("Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        // But tell DNS to use STRICT whitelist (no entertainment/social sites)
        DnsWhitelistService.SetStrictMode(true);

        ServiceLogger.Worker("EVENING MODE ACTIVE — Firewall open, DNS strict");
    }

    private void EnableWorkMode()
    {
        RunPS("Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");
        DnsWhitelistService.SetStrictMode(false);

        var remaining = RunPSOutput("(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue).Count");
        ServiceLogger.Worker($"Rules remaining after cleanup: {remaining}");
        ServiceLogger.Worker("WORK MODE ACTIVE — Full internet restored");
    }

    // ─── Tamper Detection ─────────────────────────────────────────────────────

    private void CheckForTampering()
    {
        // Only check once every 5 minutes to avoid log spam
        if ((DateTime.Now - _lastTamperCheck).TotalMinutes < 5) return;
        _lastTamperCheck = DateTime.Now;

        // Check if our firewall rules were deleted while in LOCKED mode
        if (_currentMode == "LOCKED")
        {
            var blockTcp = RunPSOutput("(Get-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -ErrorAction SilentlyContinue).Enabled");
            var blockUdp = RunPSOutput("(Get-NetFirewallRule -DisplayName 'TimeLock-Block-UDP' -ErrorAction SilentlyContinue).Enabled");

            bool tcpMissing = string.IsNullOrWhiteSpace(blockTcp) || blockTcp.Contains("False");
            bool udpMissing = string.IsNullOrWhiteSpace(blockUdp) || blockUdp.Contains("False");

            if (tcpMissing || udpMissing)
            {
                ServiceLogger.Worker("🚨 TAMPER DETECTED — Firewall rules were removed or disabled!");
                ServiceLogger.Worker("🔒 Re-applying LOCK MODE...");
                _currentMode = "UNKNOWN"; // Force re-apply
                ApplyCorrectMode();
                return;
            }
        }

        // Check if DNS server is still listening on port 53
        var dnsCheck = RunPSOutput("(Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue).Count");
        if (dnsCheck == "0" || dnsCheck == "ERROR")
        {
            ServiceLogger.Worker("⚠️ TAMPER WARNING — DNS may have been disrupted on port 53");
        }

        ServiceLogger.Worker($"✔ Tamper check passed — mode={_currentMode}");
    }

    // ─── PowerShell Helpers ───────────────────────────────────────────────────

    private void RunPS(string command)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        try
        {
            var process = Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit(15000);
                var err = process.StandardError.ReadToEnd().Trim();

                if (!string.IsNullOrEmpty(err))
                    ServiceLogger.Worker($"❌ {err[..Math.Min(err.Length, 200)]}");
                else
                    ServiceLogger.Worker($"✅ {command[..Math.Min(command.Length, 80)]}");
            }
        }
        catch (Exception ex)
        {
            ServiceLogger.Worker($"💥 {ex.Message}");
        }
    }

    private string RunPSOutput(string command)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        try
        {
            var process = Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit(10000);
                return process.StandardOutput.ReadToEnd().Trim();
            }
        }
        catch { }
        return "ERROR";
    }
}