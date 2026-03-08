namespace TimeLockService;

using System.Diagnostics;

public class Worker : BackgroundService
{
    private string _currentMode = "UNKNOWN";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Worker("Service started");
        ApplyCorrectMode();

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            ApplyCorrectMode();
            ServiceLogger.CleanupIfNeeded();
        }
    }

    private void ApplyCorrectMode()
    {
        var now = DateTime.Now.TimeOfDay;
        var workStart = new TimeSpan(8, 45, 0);
        var workEnd = new TimeSpan(17, 0, 0);

        if (now >= workStart && now <= workEnd)
        {
            if (_currentMode != "WORK")
            {
                ServiceLogger.Worker("═══════════════════════════════");
                ServiceLogger.Worker("→ SWITCHING TO WORK MODE");
                ServiceLogger.Worker("═══════════════════════════════");
                EnableWorkMode();
                _currentMode = "WORK";
            }
        }
        else
        {
            if (_currentMode != "LOCKED")
            {
                ServiceLogger.Worker("═══════════════════════════════");
                ServiceLogger.Worker("→ SWITCHING TO LOCK MODE");
                ServiceLogger.Worker("═══════════════════════════════");
                EnableLockMode();
                _currentMode = "LOCKED";
            }
        }
    }

    private void EnableLockMode()
    {
        RunPS("Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");
        ServiceLogger.Worker("Cleaned old rules");

        RunPS("New-NetFirewallRule -DisplayName 'TimeLock-Block-TCP' -Direction Outbound -Protocol TCP -Action Block -Profile Any");
        RunPS("New-NetFirewallRule -DisplayName 'TimeLock-Block-UDP' -Direction Outbound -Protocol UDP -Action Block -Profile Any");

        RunPS(@"New-NetFirewallRule -DisplayName 'TimeLock-Allow-VS' -Direction Outbound -Program 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe' -Action Allow -Profile Any");
        RunPS(@"New-NetFirewallRule -DisplayName 'TimeLock-Allow-RDP' -Direction Outbound -Program 'C:\Windows\System32\mstsc.exe' -Action Allow -Profile Any");

        ServiceLogger.Worker("LOCK MODE ACTIVE — Internet blocked");
    }

    private void EnableWorkMode()
    {
        RunPS("Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        var remaining = RunPSOutput("(Get-NetFirewallRule -DisplayName 'TimeLock*' -ErrorAction SilentlyContinue).Count");
        ServiceLogger.Worker($"Rules remaining: {remaining}");
        ServiceLogger.Worker("WORK MODE ACTIVE — Full internet restored");
    }

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
                    ServiceLogger.Worker($"❌ {err.Substring(0, Math.Min(err.Length, 200))}");
                else
                    ServiceLogger.Worker($"✅ {command.Substring(0, Math.Min(command.Length, 80))}");
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