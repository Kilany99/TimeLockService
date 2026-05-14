namespace TimeLockService;

using System.Diagnostics;

public class Worker : BackgroundService
{
    private string _currentMode = "UNKNOWN";
    private DateTime _lastTamperCheck = DateTime.MinValue;
    private DateTime _lastHealthLog = DateTime.MinValue;
    private int _consecutiveFailures = 0;

    private static readonly TimeSpan WorkStart = new(9, 0, 0);
    private static readonly TimeSpan WorkEnd = new(17, 0, 0);
    private static readonly TimeSpan EveningStart = new(17, 0, 0);
    private static readonly TimeSpan EveningEnd = new(21, 0, 0);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Worker("════════════════════════════════════════");
        ServiceLogger.Worker("   SERVICE STARTED — TimeLockService");
        ServiceLogger.Worker($"   Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        ServiceLogger.Worker($"   Running as: {Environment.UserName}");
        ServiceLogger.Worker("════════════════════════════════════════");

        // ══════════════════════════════════════════════
        // STEP 1: Force DNS to localhost IMMEDIATELY
        // ══════════════════════════════════════════════
        ServiceLogger.Worker("Setting up DNS...");
        EnforceDns();

        // Wait for DNS service to be ready (it starts in parallel)
        ServiceLogger.Worker("Waiting for DNS service to bind port 53...");
        await WaitForDnsReady(stoppingToken);

        // ══════════════════════════════════════════════
        // STEP 2: Apply correct firewall mode
        // ══════════════════════════════════════════════
        ServiceLogger.Worker("Applying firewall mode...");
        ApplyCorrectMode();

        // ══════════════════════════════════════════════
        // STEP 3: Verify everything is working
        // ══════════════════════════════════════════════
        VerifyFullSetup();

        // ══════════════════════════════════════════════
        // STEP 4: Main loop
        // ══════════════════════════════════════════════
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                ApplyCorrectMode();
                EnforceDns();
                CheckForTampering();
                LogHealthStatus();
                ServiceLogger.CleanupIfNeeded();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLogger.Worker($"💥 LOOP ERROR: {ex.Message}");
                _consecutiveFailures++;

                if (_consecutiveFailures > 5)
                {
                    ServiceLogger.Worker("🔴 TOO MANY FAILURES — Emergency lock");
                    EmergencyLock();
                }
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        ServiceLogger.Worker("════════════════════════════════════════");
        ServiceLogger.Worker("   SERVICE STOPPING");
        ServiceLogger.Worker("════════════════════════════════════════");

        RunPSWithResult(
            "Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        RunPSWithResult(
            "Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }");

        RunPSWithResult("ipconfig /flushdns");

        ServiceLogger.Worker("✅ Full cleanup complete — Internet restored");
        await base.StopAsync(cancellationToken);
    }
    // ─── Mode Application ─────────────────────────────────────────────────────

    private void ApplyCorrectMode()
    {
        var now = DateTime.Now;
        var time = now.TimeOfDay;
        var day = now.DayOfWeek;

        // Remote work days
        bool isRemoteDay = day is DayOfWeek.Sunday or DayOfWeek.Thursday;

        // Office days (you're at office — no home internet needed)
        bool isOfficeDay = day is DayOfWeek.Monday or DayOfWeek.Tuesday or DayOfWeek.Wednesday;

        // Weekend (no devices)
        bool isWeekend = day is DayOfWeek.Friday or DayOfWeek.Saturday;

        string targetMode;

        if (isWeekend)
        {
            // Friday & Saturday: FULL LOCK all day
            targetMode = "LOCKED";
        }
        else if (isOfficeDay)
        {
            // Mon/Tue/Wed: FULL LOCK all day (you're at office)
            targetMode = "LOCKED";
        }
        else if (isRemoteDay)
        {
            // Sun/Thu: Schedule-based
            if (time >= new TimeSpan(9, 0, 0) && time < new TimeSpan(17, 0, 0))
            {
                targetMode = "WORK";     // 9AM-5PM: Full internet 
            }
            else if (time >= new TimeSpan(17, 0, 0) && time < new TimeSpan(21, 0, 0))
            {
                targetMode = "EVENING";  // 5PM-9PM: Quran + essentials only
            }
            else
            {
                targetMode = "LOCKED";   // 9PM-9AM: Full lock
            }
        }
        else
        {
            targetMode = "LOCKED"; // Default: lock everything
        }

        if (_currentMode == targetMode) return;

        ServiceLogger.Worker("═══════════════════════════════");
        ServiceLogger.Worker($"→ SWITCHING: {_currentMode} → {targetMode}");
        ServiceLogger.Worker($"  Time: {now:HH:mm:ss} | Day: {day} | Remote: {isRemoteDay} | Office: {isOfficeDay} | Weekend: {isWeekend}");
        ServiceLogger.Worker("═══════════════════════════════");

        bool success = targetMode switch
        {
            "WORK" => EnableWorkMode(),
            "EVENING" => EnableEveningMode(),
            "LOCKED" => EnableLockMode(),
            _ => false
        };

        if (success)
        {
            _currentMode = targetMode;
            _consecutiveFailures = 0;
            ServiceLogger.Worker($"✅ Mode: {targetMode}");
        }
        else
        {
            _consecutiveFailures++;
            ServiceLogger.Worker($"❌ Mode switch FAILED (failures: {_consecutiveFailures})");
        }
    }

    // ─── Modes ────────────────────────────────────────────────────────────────

    private bool EnableLockMode()
    {
        bool allSuccess = true;

        // Step 1: Clean old rules
        allSuccess &= RunPSWithResult(
            "Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        // Step 2: Block all outbound
        allSuccess &= RunPSWithResult(
            "New-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -Direction Outbound -Protocol TCP -Action Block -Profile Any");
        allSuccess &= RunPSWithResult(
            "New-NetFirewallRule -DisplayName 'TimeLock-Block-UDP' -Direction Outbound -Protocol UDP -Action Block -Profile Any");

        // Step 3: Allow work tools
        allSuccess &= RunPSWithResult(
            @"New-NetFirewallRule -DisplayName 'TimeLock-Allow-VS' -Direction Outbound -Program 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe' -Action Allow -Profile Any");
        allSuccess &= RunPSWithResult(
            @"New-NetFirewallRule -DisplayName 'TimeLock-Allow-RDP' -Direction Outbound -Program 'C:\Windows\System32\mstsc.exe' -Action Allow -Profile Any");

        // Step 4: Verify rules were created
        var ruleCount = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");

        ServiceLogger.Worker($"  Lock rules created: {ruleCount} (expected: 4)");

        if (ruleCount != "4")
        {
            ServiceLogger.Worker("🔴 LOCK MODE INCOMPLETE — Not all rules were created!");
            allSuccess = false;
        }

        // Step 5: Verify block is actually working
        var blockTcp = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -ErrorAction SilentlyContinue).Enabled");
        ServiceLogger.Worker($"  Block-TCP enabled: {blockTcp}");

        DnsWhitelistService.SetStrictMode(true);

        if (allSuccess)
            ServiceLogger.Worker("🔒 LOCK MODE ACTIVE — Internet fully blocked");
        else
            ServiceLogger.Worker("⚠️ LOCK MODE PARTIAL — Some rules failed!");

        return allSuccess;
    }

    private bool EnableEveningMode()
    {
        bool success = RunPSWithResult(
            "Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        // Verify cleanup
        var remaining = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");
        ServiceLogger.Worker($"  Rules after cleanup: {remaining} (expected: 0)");

        DnsWhitelistService.SetStrictMode(true);

        ServiceLogger.Worker("🌙 EVENING MODE ACTIVE — Firewall open, DNS strict");
        return success;
    }
    private async Task WaitForDnsReady(CancellationToken stoppingToken)
    {
        int attempts = 0;
        int maxAttempts = 30; // Wait up to 30 seconds

        while (attempts < maxAttempts && !stoppingToken.IsCancellationRequested)
        {
            attempts++;

            var portCheck = RunPSOutput(
                "(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Measure-Object).Count");

            if (portCheck != "0" && portCheck != "" && portCheck != "ERROR")
            {
                ServiceLogger.Worker($"✅ DNS port 53 is ready (took {attempts} seconds)");
                return;
            }

            ServiceLogger.Worker($"⏳ Waiting for DNS port 53... ({attempts}/{maxAttempts})");
            await Task.Delay(1000, stoppingToken);
        }

        ServiceLogger.Worker("⚠️ DNS port 53 not ready after 30 seconds — continuing anyway");
    }
    private void VerifyFullSetup()
    {
        ServiceLogger.Worker("────── STARTUP VERIFICATION ──────");

        var wifiDns = RunPSOutput(
            "(Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','");
        var ethDns = RunPSOutput(
            "(Get-DnsClientServerAddress -InterfaceAlias 'Ethernet 4' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','");

        ServiceLogger.Worker($"  DNS Wi-Fi:     {wifiDns} {(wifiDns == "127.0.0.1" ? "✅" : "❌")}");
        ServiceLogger.Worker($"  DNS Ethernet:  {ethDns} {(ethDns == "127.0.0.1" ? "✅" : "❌")}");

        if (wifiDns != "127.0.0.1" || ethDns != "127.0.0.1")
        {
            ServiceLogger.Worker("  ⚠️ DNS not correct — forcing again...");
            EnforceDns();
        }

        var port53 = RunPSOutput(
            "(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Measure-Object).Count");
        ServiceLogger.Worker($"  Port 53:       {port53} listeners {(port53 != "0" ? "✅" : "❌")}");

        var ruleCount = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");
        ServiceLogger.Worker($"  FW Rules:      {ruleCount}");

        // Test actual resolution through service
        var testResolve = RunPSOutput(
            "try { (Resolve-DnsName google.com -Server 127.0.0.1 -DnsOnly -ErrorAction Stop)[0].IPAddress } catch { 'FAILED' }");
        ServiceLogger.Worker($"  DNS Test:      {testResolve} {(testResolve != "FAILED" && testResolve != "ERROR" ? "✅" : "❌")}");

        var testBlock = RunPSOutput(
            "try { (Resolve-DnsName pornhub.com -Server 127.0.0.1 -DnsOnly -ErrorAction Stop)[0].IPAddress } catch { 'BLOCKED' }");
        ServiceLogger.Worker($"  Block Test:    {testBlock} {(testBlock == "0.0.0.0" || testBlock == "BLOCKED" ? "✅" : "❌")}");

        ServiceLogger.Worker("──────────────────────────────────");
    }
    private bool EnableWorkMode()
    {
        bool success = RunPSWithResult(
            "Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        // Verify cleanup
        var remaining = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");
        ServiceLogger.Worker($"  Rules after cleanup: {remaining} (expected: 0)");

        if (remaining != "0" && remaining != "")
        {
            ServiceLogger.Worker("⚠️ WORK MODE WARNING — Some rules still exist! Force removing...");
            RunPSWithResult(
                "Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'TimeLock*'} | Remove-NetFirewallRule -Confirm:$false");
        }

        DnsWhitelistService.SetStrictMode(false);

        ServiceLogger.Worker("☀️ WORK MODE ACTIVE — Full internet restored");
        return success;
    }

    // ─── Emergency Lock (if everything is failing) ────────────────────────────

    private void EmergencyLock()
    {
        ServiceLogger.Worker("🚨🚨🚨 EMERGENCY LOCK — Attempting direct firewall command 🚨🚨🚨");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            var p = Process.Start(psi);
            p?.WaitForExit(10000);
            ServiceLogger.Worker("🚨 Emergency lock applied via netsh");
        }
        catch (Exception ex)
        {
            ServiceLogger.Worker($"🚨 Emergency lock FAILED: {ex.Message}");
        }
    }

    // ─── Tamper Detection ─────────────────────────────────────────────────────

    private void CheckForTampering()
    {
        if ((DateTime.Now - _lastTamperCheck).TotalMinutes < 2) return;
        _lastTamperCheck = DateTime.Now;

        if (_currentMode == "LOCKED")
        {
            var ruleCount = RunPSOutput(
                "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");

            int count = 0;
            int.TryParse(ruleCount, out count);

            if (count < 4)
            {
                ServiceLogger.Worker($"🚨 TAMPER DETECTED — Only {count}/4 rules found!");
                ServiceLogger.Worker("🔒 Re-applying LOCK MODE...");
                _currentMode = "UNKNOWN";
                ApplyCorrectMode();
                return;
            }

            // Verify rules are enabled
            var tcpEnabled = RunPSOutput(
                "(Get-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -ErrorAction SilentlyContinue).Enabled");
            var udpEnabled = RunPSOutput(
                "(Get-NetFirewallRule -DisplayName 'TimeLock-Block-UDP' -ErrorAction SilentlyContinue).Enabled");
            // Check DNS guard rules exist
            var dnsGuardRule = RunPSOutput(
                "(Get-NetFirewallRule -DisplayName 'DnsGuard-Block-ExtDNS-UDP' -ErrorAction SilentlyContinue).Enabled");

            if (dnsGuardRule != "True")
            {
                ServiceLogger.Worker("🚨 DNS GUARD MISSING — Recreating...");
                EnforceDns();
            }
            if (tcpEnabled != "True" || udpEnabled != "True")
            {
                ServiceLogger.Worker($"🚨 TAMPER DETECTED — Rules disabled! TCP={tcpEnabled} UDP={udpEnabled}");
                _currentMode = "UNKNOWN";
                ApplyCorrectMode();
                return;
            }

            ServiceLogger.Worker($"✔ Tamper check OK — {count} rules active");
        }
    }

    // ─── Health Logging ───────────────────────────────────────────────────────

    private void LogHealthStatus()
    {
        if ((DateTime.Now - _lastHealthLog).TotalMinutes < 30) return;
        _lastHealthLog = DateTime.Now;

        var ruleCount = RunPSOutput(
            "(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Measure-Object).Count");

        var dnsServer = RunPSOutput(
            "(Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ErrorAction SilentlyContinue).ServerAddresses -join ','");

        var dnsServerEth = RunPSOutput(
            "(Get-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ErrorAction SilentlyContinue).ServerAddresses -join ','");

        ServiceLogger.Worker("────── HEALTH CHECK ──────");
        ServiceLogger.Worker($"  Mode:          {_currentMode}");
        ServiceLogger.Worker($"  Time:          {DateTime.Now:HH:mm:ss}");
        ServiceLogger.Worker($"  Day:           {DateTime.Now.DayOfWeek}");
        ServiceLogger.Worker($"  FW Rules:      {ruleCount}");
        ServiceLogger.Worker($"  DNS (WiFi):    {dnsServer}");
        ServiceLogger.Worker($"  DNS (Ethernet): {dnsServerEth}");
        ServiceLogger.Worker($"  Strict DNS:    {(_currentMode != "WORK" ? "YES" : "NO")}");
        ServiceLogger.Worker($"  Failures:      {_consecutiveFailures}");
        ServiceLogger.Worker("──────────────────────────");
    }

    // ─── PowerShell Helpers ───────────────────────────────────────────────────

    private bool RunPSWithResult(string command)
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
                var output = process.StandardOutput.ReadToEnd().Trim();

                if (!string.IsNullOrEmpty(err))
                {
                    ServiceLogger.Worker($"❌ CMD: {command[..Math.Min(command.Length, 60)]}");
                    ServiceLogger.Worker($"   ERR: {err[..Math.Min(err.Length, 200)]}");
                    return false;
                }

                ServiceLogger.Worker($"✅ {command[..Math.Min(command.Length, 80)]}");
                return true;
            }
        }
        catch (Exception ex)
        {
            ServiceLogger.Worker($"💥 CMD: {command[..Math.Min(command.Length, 60)]}");
            ServiceLogger.Worker($"   EXC: {ex.Message}");
        }
        return false;
    }

    private void RunPS(string command) => RunPSWithResult(command);

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
        catch (Exception ex)
        {
            ServiceLogger.Worker($"💥 OUTPUT CMD FAILED: {ex.Message}");
        }
        return "ERROR";
    }
    private void EnforceDns()
    {
        // Force DNS to localhost on ALL active adapters
        RunPSWithResult(
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1' }");

        RunPSWithResult(
            "Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue");
        RunPSWithResult(
            "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet 4' -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue");
        RunPSWithResult(
            "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet 3' -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue");

        RunPSWithResult("ipconfig /flushdns");

        ServiceLogger.Worker("✅ DNS enforcement complete");
    }
}