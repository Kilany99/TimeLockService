namespace TimeLockService;

using System.Net;
using System.Net.Sockets;
using DNS.Server;
using DNS.Client;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using System.Security.Cryptography;
using System.Text;

public class DnsWhitelistService : BackgroundService
{
    // ─── Strict Mode (controlled by Worker) ──────────────────────────────────
    // When true: only _strictWhitelist is used (evenings/weekends/locked)
    // When false: full _whitelist is used (work hours)
    private static volatile bool _strictModeEnabled = false;
    public static void SetStrictMode(bool enabled) => _strictModeEnabled = enabled;

    // ─── Password for whitelist editing ──────────────────────────────────────
    private const string PasswordHash = "1039df0151acd34cf00342300a0b9e6a21fd529552dcc71ad497abe2bc1c24a9";

    // ─── Counters for daily summary ───────────────────────────────────────────
    private static int _allowedToday = 0;
    private static int _blockedToday = 0;
    private static DateTime _summaryDate = DateTime.Today;
    private static readonly object _counterLock = new();

    public static void IncrementAllowed() { lock (_counterLock) _allowedToday++; }
    public static void IncrementBlocked() { lock (_counterLock) _blockedToday++; }

    // ─── Full whitelist (work hours) ─────────────────────────────────────────
    private readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft / Work
        "login.microsoftonline.com",
        "portal.azure.com",
        "teams.microsoft.com",
        "outlook.office365.com",
        "outlook.office.com",
        "microsoft.com",
        "outlook.live.com",
        "office.com",
        "office365.com",
        "sharepoint.com",
        "windows.net",
        "microsoftonline.com",
        "visualstudio.com",
        "dev.azure.com",
        "nuget.org",
        "dotnet.microsoft.com",
        "learn.microsoft.com",

        // Your work & personal
        "meet.google.com",
        "surahquran.com",
        "uboxksa.com",
        "app.alignerr.com",
        "github.com",
        "stackoverflow.com",
        "google.com",
        "www.google.com",
        "gmail.com",
        "mail.google.com",
        "whatsapp.com",
        "web.whatsapp.com",
        "playground.outlier.ai",
        "chatgpt.com",
        "claude.ai",
        "docs.myfatoorah.com",
        "qudratech.visualstudio.com",
        "aircairo.com",
        "grok.com",
        "gemini.google.com",
        "developers.tap.company",
        "www.mp3quran.net",

        // Microsoft Authentication
        "login.live.com",
        "account.live.com",
        "auth.microsoft.com",
        "aadcdn.msftauth.net",
        "msftauth.net",
        "msauth.net",
        "aadcdn.msauth.net",
        "logincdn.msftauth.net",

        // Microsoft Teams
        "teams.cdn.office.net",
        "statics.teams.cdn.office.net",
        "lync.com",
        "skype.com",
        "trouter.teams.microsoft.com",
        "substrate.office.com",
        "presence.teams.microsoft.com",
        "notifications.teams.microsoft.com",

        // Outlook / Email
        "attachments.office.net",
        "smtp.office365.com",
        "protection.outlook.com",
        "autodiscover.outlook.com",

        // Azure DevOps / Visual Studio
        "vsassets.io",
        "vsmarketplacebadges.dev",
        "gallerycdn.vsassets.io",
        "marketplace.visualstudio.com",
        "vscode.dev",
        "update.code.visualstudio.com",
        "az764295.vo.msecnd.net",

        // NuGet
        "api.nuget.org",
        "globalcdn.nuget.org",
        "azureedge.net",

        // GitHub
        "githubusercontent.com",
        "raw.githubusercontent.com",
        "github.githubassets.com",
        "avatars.githubusercontent.com",
        "codeload.github.com",
        "copilot.github.com",
        "api.github.com",

        // Google Services
        "googleapis.com",
        "gstatic.com",
        "google-analytics.com",
        "googleusercontent.com",
        "accounts.google.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "ssl.gstatic.com",
        "apis.google.com",
        "play.google.com",

        // ChatGPT
        "openai.com",
        "api.openai.com",
        "cdn.openai.com",
        "auth0.openai.com",
        "oaiusercontent.com",

        // Claude AI
        "anthropic.com",
        "api.anthropic.com",
        "cdn.claude.ai",
        "claude.com",
        "s-cdn.anthropic.com",

        // Grok
        "api.x.com",
        "abs.twimg.com",
        "pbs.twimg.com",
        "twimg.com",

        // WhatsApp
        "whatsapp.net",
        "wa.me",
        "mmg.whatsapp.net",

        // Stack Overflow
        "cdn.sstatic.net",
        "sstatic.net",
        "stackexchange.com",
        "ajax.googleapis.com",

        // Outlier / Alignerr
        "outlier.ai",
        "alignerr.com",
        "cdn.alignerr.com",

        // CDNs
        "cloudflare.com",
        "cdnjs.cloudflare.com",
        "cdn.cloudflare.com",
        "cloudflare-dns.com",
        "ajax.cloudflare.com",
        "jsdelivr.net",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "fastly.net",
        "akamaized.net",
        "akamai.net",
        "cloudfront.net",
        "bootstrapcdn.com",

        // Windows System
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "download.windowsupdate.com",
        "www.msftconnecttest.com",
        "dns.msftncsi.com",
        "ctldl.windowsupdate.com",
        "crl.microsoft.com",
        "ocsp.digicert.com",
        "ocsp.globalsign.com",
        "ocsp.sectigo.com",
        "crl3.digicert.com",
        "crl4.digicert.com",
        "digicert.com",
        "symantec.com",
        "verisign.com",
        "letsencrypt.org",
        "r3.o.lencr.org",
        "x1.c.lencr.org",
        "activation.sls.microsoft.com",
        "validation.sls.microsoft.com",
        "settings-win.data.microsoft.com",
        "watson.telemetry.microsoft.com",
        "v10.events.data.microsoft.com",
        "time.windows.com",
        "time.nist.gov",

        // Quran / Islamic
        "mp3quran.net",
        "www.mp3quran.net",
        "cdn.mp3quran.net",
        "server6.mp3quran.net",
        "server8.mp3quran.net",
        "server10.mp3quran.net",
        "server11.mp3quran.net",
        "server12.mp3quran.net",
        "server13.mp3quran.net",
        "server14.mp3quran.net",
        "server16.mp3quran.net",
        "quran.com",
        "www.quran.com",
        "api.quran.com",
        "api.qurancdn.com",
        "audio.qurancdn.com",
        "verses.quran.com",
        "cdn.qurancdn.com",
        "qurancdn.com",
        "images.qurancdn.com",
        "surahquran.com",
        "www.surahquran.com",
        "quranicaudio.com",
        "www.quranicaudio.com",
        "download.quranicaudio.com",
        "mirrors.quranicaudio.com",
        "everyayah.com",
        "www.everyayah.com",
        "audio.everyayah.com",
        "alquran.cloud",
        "api.alquran.cloud",
        "cdn.alquran.cloud",
        "media.alquran.cloud",
        "islamway.net",
        "www.islamway.net",
        "en.islamway.net",
        "ar.islamway.net",
        "sunnah.com",
        "www.sunnah.com",
        "api.sunnah.com",
        "tarteel.ai",
        "www.tarteel.ai",
        "api.tarteel.ai",
        "quranexplorer.com",
        "www.quranexplorer.com",
        "almushaf.net",
        "www.almushaf.net",
        "ayat.qurancomplex.gov.sa",
        "qurancomplex.gov.sa",
        "www.qurancomplex.gov.sa",
        "azkar.app",
        "www.azkar.app",
        "hisnmuslim.com",
        "www.hisnmuslim.com",
        "haramain.info",
        "www.haramain.info",
        "aladhan.com",
        "api.aladhan.com",
        "www.aladhan.com",
        "qtafsir.com",
        "www.qtafsir.com",
        "tafsir.com",
        "www.tafsir.com",
        "altafsir.com",
        "archive.org",
        "www.archive.org",
        "ia800.us.archive.org",
        "ia801.us.archive.org",
        "ia802.us.archive.org",
        "ia803.us.archive.org",
        "ia804.us.archive.org",
        "ia805.us.archive.org",
        "ia600.us.archive.org",
        "ia601.us.archive.org",

        // Developer Tools
        "visualstudio.microsoft.com",
        "download.visualstudio.microsoft.com",
        "vsstartpage.blob.core.windows.net",
        "dc.services.visualstudio.com",
        "vortex.data.microsoft.com",
        "intellicode.visualstudio.com",
        "prod.intellicode.vsengsaas.visualstudio.com",
        "developercommunity.visualstudio.com",
        "code.visualstudio.com",
        "update.code.visualstudio.com",
        "vscode.dev",
        "vscode.blob.core.windows.net",
        "vscodeuserdata.blob.core.windows.net",
        "default.exp-tas.com",
        "copilot.github.com",
        "api.githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        "download.microsoft.com",
        "go.microsoft.com",
        "database.windows.net",
        "core.windows.net",
        "blob.core.windows.net",
        "watson.microsoft.com",
        "dotnetcli.azureedge.net",
        "dotnetfeed.blob.core.windows.net",
        "azure.com",
        "management.azure.com",
        "graph.microsoft.com",
        "az764295.vo.msecnd.net",
        "sendvsfeedback2.azurewebsites.net",
        "targetednotifications-tm.trafficmanager.net",
        "azurewebsites.net",
        "trafficmanager.net",
        "telemetry.individual.githubcopilot.com",
        "individual.githubcopilot.com",
        "cdn.auth0.com",
        "auth0.com",
        "browser-intake-datadoghq.com",
        "datadoghq.com",
        "ipv6.msftncsi.com",
        "www.msftncsi.com",
        "msftncsi.com",
        "v10.events.data.microsoft.com",
        "v20.events.data.microsoft.com",
        "mobile.events.data.microsoft.com",
        "watson.events.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "edge.microsoft.com",
        "msecnd.net",
        "vo.msecnd.net",
        "dsp.mp.microsoft.com",

        "docs.tabby.ai",
        "docs.tamara.co",
    };

    // ─── Strict whitelist (evenings/weekends/locked) ──────────────────────────
    // Contains only essential domains — no social, no entertainment
    private readonly HashSet<string> _strictWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Work essentials only
        "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
        "login.microsoftonline.com", "login.live.com", "auth.microsoft.com",
        "msftauth.net", "msauth.net", "aadcdn.msftauth.net", "aadcdn.msauth.net",
        "teams.microsoft.com", "outlook.office365.com", "sharepoint.com",
        "visualstudio.com", "dev.azure.com", "github.com", "githubusercontent.com",
        "nuget.org", "api.nuget.org",

        // Islamic / Quran (always allowed)
        "quran.com", "www.quran.com", "api.quran.com", "qurancdn.com",
        "audio.qurancdn.com", "api.qurancdn.com",
        "mp3quran.net", "www.mp3quran.net", "cdn.mp3quran.net",
        "server6.mp3quran.net", "server8.mp3quran.net", "server10.mp3quran.net",
        "server11.mp3quran.net", "server12.mp3quran.net", "server13.mp3quran.net",
        "server14.mp3quran.net", "server16.mp3quran.net",
        "surahquran.com", "www.surahquran.com",
        "quranicaudio.com", "www.quranicaudio.com", "download.quranicaudio.com",
        "everyayah.com", "audio.everyayah.com",
        "alquran.cloud", "api.alquran.cloud",
        "sunnah.com", "www.sunnah.com", "api.sunnah.com",
        "tarteel.ai", "api.tarteel.ai",
        "aladhan.com", "api.aladhan.com",
        "islamway.net", "ar.islamway.net",
        "hisnmuslim.com", "azkar.app",
        "qurancomplex.gov.sa", "ayat.qurancomplex.gov.sa",
        "haramain.info",

        // Windows system (always needed)
        "windowsupdate.microsoft.com", "update.microsoft.com",
        "www.msftconnecttest.com", "dns.msftncsi.com",
        "ctldl.windowsupdate.com", "crl.microsoft.com",
        "ocsp.digicert.com", "digicert.com",
        "letsencrypt.org", "r3.o.lencr.org",
        "time.windows.com", "time.nist.gov",
        "activation.sls.microsoft.com", "validation.sls.microsoft.com",

        // CDN essentials
        "cloudflare.com", "cdnjs.cloudflare.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
        "gstatic.com",
    };

    // ─── Dynamic extra entries (password-protected editing) ──────────────────
    private static readonly HashSet<string> _dynamicEntries = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _dynamicLock = new();

    // ─── Password-protected add/remove API ───────────────────────────────────

    /// <summary>
    /// Returns true if the password is correct and the domain was added.
    /// </summary>
    public static bool TryAddDomain(string password, string domain)
    {
        if (!VerifyPassword(password)) return false;
        lock (_dynamicLock)
        {
            _dynamicEntries.Add(domain.ToLowerInvariant().Trim());
        }
        ServiceLogger.Dns($"🔓 Domain added via password: {domain}");
        return true;
    }

    /// <summary>
    /// Returns true if the password is correct and the domain was removed.
    /// </summary>
    public static bool TryRemoveDomain(string password, string domain)
    {
        if (!VerifyPassword(password)) return false;
        lock (_dynamicLock)
        {
            _dynamicEntries.Remove(domain.ToLowerInvariant().Trim());
        }
        ServiceLogger.Dns($"🔓 Domain removed via password: {domain}");
        return true;
    }

    private static bool VerifyPassword(string input)
    {
        var hash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(input))
        ).ToLower();

        bool ok = hash == PasswordHash.ToLower();
        if (!ok) ServiceLogger.Dns($"🚫 Invalid password attempt");
        return ok;
    }

    // ─── Background service ───────────────────────────────────────────────────

    public DnsWhitelistService() { }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Dns("DNS Whitelist starting...");

        var resolver = new WhitelistRequestResolver(GetActiveWhitelist, _dynamicEntries);
        var server = new DnsServer(resolver);

        server.Listening += (s, e) =>
            ServiceLogger.Dns("✅ DNS Whitelist ACTIVE on port 53");

        server.Errored += (s, e) =>
            ServiceLogger.Dns($"⚠️ DNS error: {e.Exception.Message}");

        try
        {
            var dnsTask = Task.Run(() => server.Listen(53, IPAddress.Loopback), stoppingToken);

            while (!stoppingToken.IsCancellationRequested && !dnsTask.IsCompleted)
            {
                await Task.Delay(1000, stoppingToken);
                WriteDailySummaryIfNeeded();
            }
        }
        catch (SocketException ex)
        {
            ServiceLogger.Dns($"⚠️ Port 53 unavailable: {ex.Message}");
            ServiceLogger.Dns("DNS disabled — Firewall lock still active");

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(30000, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            ServiceLogger.Dns("DNS stopping");
        }
        catch (Exception ex)
        {
            ServiceLogger.Dns($"DNS unexpected error: {ex.Message}");

            while (!stoppingToken.IsCancellationRequested)
                await Task.Delay(30000, stoppingToken);
        }
    }

    // ─── Daily summary ────────────────────────────────────────────────────────

    private void WriteDailySummaryIfNeeded()
    {
        var today = DateTime.Today;
        if (today <= _summaryDate) return;

        int allowed, blocked;
        lock (_counterLock)
        {
            allowed = _allowedToday;
            blocked = _blockedToday;
            _allowedToday = 0;
            _blockedToday = 0;
            _summaryDate = today;
        }

        ServiceLogger.Dns("════════════════════════════════════");
        ServiceLogger.Dns($"📊 DAILY SUMMARY for {today.AddDays(-1):yyyy-MM-dd}");
        ServiceLogger.Dns($"   ✅ Allowed:  {allowed} queries");
        ServiceLogger.Dns($"   🚫 Blocked:  {blocked} queries");
        ServiceLogger.Dns($"   📈 Total:    {allowed + blocked} queries");
        if (allowed + blocked > 0)
        {
            var pct = (blocked * 100.0) / (allowed + blocked);
            ServiceLogger.Dns($"   🔒 Block rate: {pct:F1}%");
        }
        ServiceLogger.Dns("════════════════════════════════════");
    }

    // ─── Active whitelist selector ────────────────────────────────────────────

    private HashSet<string> GetActiveWhitelist()
        => _strictModeEnabled ? _strictWhitelist : _whitelist;
}