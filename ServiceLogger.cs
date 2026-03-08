namespace TimeLockService;

public static class ServiceLogger
{
    private static readonly string LogDir = @"C:\TimeLockService";
    private static readonly object _lock = new();
    private static DateTime _lastCleanup = DateTime.MinValue;

    public static void Worker(string msg)
    {
        Write("worker.log", msg);
    }

    public static void Dns(string msg)
    {
        Write("dns.log", msg);
    }

    public static void CleanupIfNeeded()
    {
        var now = DateTime.Now;
        if (now.Date > _lastCleanup.Date)
        {
            try
            {
                lock (_lock)
                {
                    foreach (var logFile in new[] { "worker.log", "dns.log" })
                    {
                        var path = Path.Combine(LogDir, logFile);
                        if (File.Exists(path))
                        {
                            File.WriteAllText(path,
                                $"[{now:yyyy-MM-dd HH:mm:ss}] === LOG CLEARED ===\n");
                        }
                    }
                    _lastCleanup = now;
                    Worker(" Logs cleaned at midnight");
                }
            }
            catch { }
        }
    }

    private static void Write(string fileName, string msg)
    {
        try
        {
            lock (_lock)
            {
                Directory.CreateDirectory(LogDir);
                File.AppendAllText(
                    Path.Combine(LogDir, fileName),
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {msg}\n");
            }
        }
        catch { }
    }
}