namespace TimeLockService;

using System.Net;
using System.Net.Sockets;
using DNS.Server;
using DNS.Client;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

public class DnsWhitelistService : BackgroundService
{
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
    
    
    // --- Microsoft Authentication (REQUIRED) ---
    "login.live.com",
    "account.live.com",
    "auth.microsoft.com",
    "aadcdn.msftauth.net",
    "msftauth.net",
    "msauth.net",
    "aadcdn.msauth.net",
    "logincdn.msftauth.net",
    
    // --- Microsoft Teams Dependencies ---
    "teams.cdn.office.net",
    "statics.teams.cdn.office.net",
    "lync.com",
    "skype.com",
    "trouter.teams.microsoft.com",
    "substrate.office.com",
    "presence.teams.microsoft.com",
    "notifications.teams.microsoft.com",
    
    // --- Outlook / Email Dependencies ---
    "attachments.office.net",
    "smtp.office365.com",
    "protection.outlook.com",
    "autodiscover.outlook.com",
    
    // --- Azure DevOps / Visual Studio ---
    "vsassets.io",
    "vsmarketplacebadges.dev",
    "gallerycdn.vsassets.io",
    "marketplace.visualstudio.com",
    "vscode.dev",
    "update.code.visualstudio.com",
    "az764295.vo.msecnd.net",
    
    // --- NuGet Dependencies ---
    "api.nuget.org",
    "globalcdn.nuget.org",
    "azureedge.net",
    
    // --- GitHub Dependencies ---
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "github.githubassets.com",
    "avatars.githubusercontent.com",
    "codeload.github.com",
    "copilot.github.com",
    "api.github.com",
    
    // --- Google Services Dependencies ---
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
    
    // --- ChatGPT Dependencies ---
    "openai.com",
    "api.openai.com",
    "cdn.openai.com",
    "auth0.openai.com",
    "oaiusercontent.com",
    
    // --- Claude AI Dependencies ---
    "anthropic.com",
    "api.anthropic.com",
    "cdn.claude.ai",
    "claude.com",
    "s-cdn.anthropic.com",
    
    // --- Grok Dependencies ---
    //"x.ai",
    "api.x.com",
    "abs.twimg.com",
    "pbs.twimg.com",
    "twimg.com",
    
    // --- WhatsApp Dependencies ---
    "whatsapp.net",
    "wa.me",
    "mmg.whatsapp.net",
    
    // --- Stack Overflow Dependencies ---
    "cdn.sstatic.net",
    "sstatic.net",
    "stackexchange.com",
    "ajax.googleapis.com",
    
    // --- Outlier / Alignerr Dependencies ---
    "outlier.ai",
    "alignerr.com",
    "cdn.alignerr.com",
    
    // ============================================
    // 🟡 COMMON CDNs — Many sites need these
    // ============================================
    
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
    
    // ============================================
    // 🟡 WINDOWS SYSTEM — Required for OS to work
    // ============================================
    
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
    
    // Windows activation & telemetry (needed)
    "activation.sls.microsoft.com",
    "validation.sls.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "v10.events.data.microsoft.com",
    
    // Windows time sync
    "time.windows.com",
    "time.nist.gov",
    
// ============================================
// 🕌 QURAN / ISLAMIC 
// ============================================

// --- MP3 Quran ---
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

// --- Quran.com (Most Popular) ---
"quran.com",
"www.quran.com",
"api.quran.com",
"api.qurancdn.com",
"audio.qurancdn.com",
"verses.quran.com",
"cdn.qurancdn.com",
"qurancdn.com",
"images.qurancdn.com",

// --- Surah Quran ---
"surahquran.com",
"www.surahquran.com",

// --- Quran Player / Recitation ---
"quranicaudio.com",
"www.quranicaudio.com",
"download.quranicaudio.com",
"mirrors.quranicaudio.com",
"everyayah.com",
"www.everyayah.com",
"audio.everyayah.com",

// --- Al Quran Cloud API ---
"alquran.cloud",
"api.alquran.cloud",
"cdn.alquran.cloud",
"media.alquran.cloud",

// --- Islamway ---
"islamway.net",
"www.islamway.net",
"en.islamway.net",
"ar.islamway.net",

// --- Sunnah / Hadith ---
"sunnah.com",
"www.sunnah.com",
"api.sunnah.com",

// --- Tarteel AI (Quran Recognition) ---
"tarteel.ai",
"www.tarteel.ai",
"api.tarteel.ai",

// --- Quran Explorer ---
"quranexplorer.com",
"www.quranexplorer.com",

// --- Al Mushaf ---
"almushaf.net",
"www.almushaf.net",

// --- Ayat App ---
"ayat.qurancomplex.gov.sa",
"qurancomplex.gov.sa",
"www.qurancomplex.gov.sa",

// --- Zekr / Athkar ---
"azkar.app",
"www.azkar.app",
"hisnmuslim.com",
"www.hisnmuslim.com",

// --- Makkah & Madinah Live ---
"haramain.info",
"www.haramain.info",

// --- Islamic Prayer Times ---
"aladhan.com",
"api.aladhan.com",
"www.aladhan.com",

// --- Quran Tafsir ---
"qtafsir.com",
"www.qtafsir.com",
"tafsir.com",
"www.tafsir.com",
"altafsir.com",

// --- Archive.org (Many Quran recordings hosted here) ---
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

// --- CDNs Used By Quran Sites ---
"cdn.jsdelivr.net",          
"cloudflare.com",            
"fonts.googleapis.com",      
"fonts.gstatic.com",         
    // ============================================
// 🛠️ DEVELOPER TOOLS — IDE & DATABASE
// ============================================

// --- Visual Studio 2022 ---
"visualstudio.microsoft.com",
"download.visualstudio.microsoft.com",
"vsstartpage.blob.core.windows.net",
"dc.services.visualstudio.com",
"vortex.data.microsoft.com",
"intellicode.visualstudio.com",
"prod.intellicode.vsengsaas.visualstudio.com",
"developercommunity.visualstudio.com",

// --- VS Code ---
"code.visualstudio.com",
"update.code.visualstudio.com",
"vscode.dev",
"vscode.blob.core.windows.net",
"vscodeuserdata.blob.core.windows.net",
"default.exp-tas.com",

// --- GitHub Copilot ---
"copilot.github.com",
"api.githubcopilot.com",
"copilot-proxy.githubusercontent.com",

// --- SQL Server / SSMS ---
"download.microsoft.com",
"go.microsoft.com",
"database.windows.net",
"core.windows.net",
"blob.core.windows.net",
"watson.microsoft.com",

// --- .NET SDK ---
"dotnetcli.azureedge.net",
"dotnetfeed.blob.core.windows.net",

// --- NuGet (expanded) ---
"api.nuget.org",
"globalcdn.nuget.org",

// --- General Azure ---
"azure.com",
"management.azure.com",
"graph.microsoft.com",

"az764295.vo.msecnd.net",
"sendvsfeedback2.azurewebsites.net",
"targetednotifications-tm.trafficmanager.net",
"azurewebsites.net",                         // Many MS services use this
"trafficmanager.net",                        // Microsoft load balancer

// --- GitHub Copilot Telemetry ---
"telemetry.individual.githubcopilot.com",
"individual.githubcopilot.com",

// --- Auth0 (Used by ChatGPT & others) ---
"cdn.auth0.com",
"auth0.com",

// --- DataDog (Used by some apps) ---
"browser-intake-datadoghq.com",
"datadoghq.com",

// --- Microsoft Network Check ---
"ipv6.msftncsi.com",
"www.msftncsi.com",
"msftncsi.com",

// --- Microsoft Events/Telemetry ---
"v10.events.data.microsoft.com",
"v20.events.data.microsoft.com",
"mobile.events.data.microsoft.com",
"watson.events.data.microsoft.com",
"settings-win.data.microsoft.com",
"edge.microsoft.com",

// --- Microsoft CDN & Download ---
"msecnd.net",
"vo.msecnd.net",
"dsp.mp.microsoft.com",


"docs.tabby.ai",
"docs.tamara.co",

};

    public DnsWhitelistService() { }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ServiceLogger.Dns("DNS Whitelist starting...");

        var resolver = new WhitelistRequestResolver(_whitelist);
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
}