namespace TimeLockService;

public static class ServiceLogger
{
    private static readonly string LogDir = @"C:\TimeLockService";
    private static readonly object _lock = new();
    private static DateTime _lastCleanup = DateTime.MinValue;

    public static void Worker(string msg) => Write("worker.log", msg);
    public static void Dns(string msg) => Write("dns.log", msg);

    /// <summary>
    /// Clears both logs once per day (at any hour, not just midnight).
    /// Call this from the Worker loop every minute.
    /// </summary>
    public static void CleanupIfNeeded()
    {
        var now = DateTime.Now;

        // Fire once per calendar day — no hour restriction
        if (now.Date <= _lastCleanup.Date) return;

        try
        {
            lock (_lock)
            {
                // Double-check inside lock to avoid race
                if (now.Date <= _lastCleanup.Date) return;

                foreach (var logFile in new[] { "worker.log", "dns.log" })
                {
                    var path = Path.Combine(LogDir, logFile);
                    if (File.Exists(path))
                    {
                        // Keep last 50 lines so we don't lose the day's summary
                        var lines = File.ReadAllLines(path);
                        var keep = lines.TakeLast(50).ToArray();

                        File.WriteAllLines(path, new[]
                        {
                            $"[{now:yyyy-MM-dd HH:mm:ss}] ═══ LOG ROTATED (kept last {keep.Length} lines) ═══"
                        }.Concat(keep));
                    }
                }

                _lastCleanup = now;
                Worker($"🗑️ Logs rotated for {now:yyyy-MM-dd}");
            }
        }
        catch { /* never crash the service over logging */ }
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