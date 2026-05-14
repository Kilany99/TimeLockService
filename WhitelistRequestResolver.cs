namespace TimeLockService;

using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using DNS.Server;
using System.Collections.Concurrent;
using System.Net;

public class WhitelistRequestResolver : IRequestResolver
{
    private readonly Func<HashSet<string>> _getWhitelist;
    private readonly HashSet<string> _dynamicEntries;

    // DNS Cache — avoids hitting upstream for every single query
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    private class CacheEntry
    {
        public List<IPAddressResourceRecord> Records { get; set; } = new();
        public DateTime Expiry { get; set; }
        public bool IsExpired => DateTime.Now > Expiry;
    }

    // Single upstream client with longer timeout
    private readonly DnsClient _upstream;

    public WhitelistRequestResolver(
        Func<HashSet<string>> getWhitelist,
        HashSet<string> dynamicEntries)
    {
        _getWhitelist = getWhitelist;
        _dynamicEntries = dynamicEntries;
        _upstream = new DnsClient("1.1.1.1");
    }

    public async Task<IResponse> Resolve(IRequest request,
    CancellationToken cancellationToken = default)
    {
        IResponse response = Response.FromRequest(request);

        foreach (var question in request.Questions)
        {
            string domain = question.Name.ToString().TrimEnd('.');

            try
            {
                // ══════════════════════════════════════
                // HARD BLOCK: YouTube — Always blocked
                // ══════════════════════════════════════
                if (IsYouTubeDomain(domain))
                {
                    ServiceLogger.Dns($"🚫 YOUTUBE BLOCKED: {domain}");
                    DnsWhitelistService.IncrementBlocked();
                    var record = new IPAddressResourceRecord(
                        question.Name, IPAddress.Any, TimeSpan.FromMinutes(30));
                    ((Response)response).AnswerRecords.Add(record);
                    continue;
                }

                // ══════════════════════════════════════
                // HARD BLOCK: Google Search — Always blocked
                // ══════════════════════════════════════
                if (IsGoogleSearchDomain(domain))
                {
                    ServiceLogger.Dns($"🚫 GOOGLE SEARCH BLOCKED: {domain}");
                    DnsWhitelistService.IncrementBlocked();
                    var record = new IPAddressResourceRecord(
                        question.Name, IPAddress.Any, TimeSpan.FromMinutes(30));
                    ((Response)response).AnswerRecords.Add(record);
                    continue;
                }

                // ══════════════════════════════════════
                // NORMAL WHITELIST CHECK
                // ══════════════════════════════════════
                if (IsWhitelisted(domain))
                {
                    ServiceLogger.Dns($"✅ ALLOWED: {domain}");
                    DnsWhitelistService.IncrementAllowed();
                    await ResolveAndAdd(response, question, domain);
                }
                else
                {
                    ServiceLogger.Dns($"🚫 BLOCKED: {domain}");
                    DnsWhitelistService.IncrementBlocked();
                    var record = new IPAddressResourceRecord(
                        question.Name, IPAddress.Any, TimeSpan.FromMinutes(5));
                    ((Response)response).AnswerRecords.Add(record);
                }
            }
            catch (Exception ex)
            {
                ServiceLogger.Dns($"⚠️ Error processing {domain}: {ex.Message}");
            }
        }

        return response;
    }
    // ─── Cached DNS Resolution ────────────────────────────────────────────

    private async Task ResolveAndAdd(IResponse response, Question question, string resolveDomain)
    {
        string cacheKey = $"{resolveDomain}:{question.Type}";

        // Check cache first
        if (_cache.TryGetValue(cacheKey, out var cached) && !cached.IsExpired)
        {
            foreach (var record in cached.Records)
                ((Response)response).AnswerRecords.Add(record);
            return;
        }

        // Resolve upstream with timeout
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));

            var upstreamResponse = await _upstream.Resolve(resolveDomain, question.Type);

            // Cache the result
            var entry = new CacheEntry
            {
                Expiry = DateTime.Now.Add(CacheDuration)
            };

            foreach (var answer in upstreamResponse.AnswerRecords)
            {
                ((Response)response).AnswerRecords.Add(answer);

                if (answer is IPAddressResourceRecord ipRecord)
                    entry.Records.Add(ipRecord);
            }

            if (entry.Records.Count > 0)
                _cache[cacheKey] = entry;
        }
        catch (Exception ex)
        {
            ServiceLogger.Dns($"⏱️ UPSTREAM FAILED for {resolveDomain}: {ex.Message}");

            // Try cache even if expired (stale is better than nothing)
            if (_cache.TryGetValue(cacheKey, out var stale))
            {
                ServiceLogger.Dns($"📦 Using stale cache for {resolveDomain}");
                foreach (var record in stale.Records)
                    ((Response)response).AnswerRecords.Add(record);
            }
        }
    }

    // ─── Domain Checks ────────────────────────────────────────────────────

    private bool IsYouTubeDomain(string domain)
    {
        // Block EVERYTHING YouTube related
        if (domain.Contains("youtube", StringComparison.OrdinalIgnoreCase)) return true;
        if (domain.Contains("ytimg", StringComparison.OrdinalIgnoreCase)) return true;
        if (domain.Contains("googlevideo", StringComparison.OrdinalIgnoreCase)) return true;
        if (domain.Contains("youtu.be", StringComparison.OrdinalIgnoreCase)) return true;
        if (domain.Contains("yt3.ggpht", StringComparison.OrdinalIgnoreCase)) return true;
        if (domain.Contains("youtubei", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private bool IsGoogleSearchDomain(string domain)
    {
        // Block Google Search but NOT other Google services
        return domain.Equals("www.google.com", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("google.com", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("www.google.com.sa", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("google.com.sa", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("www.google.co.uk", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("google.co.uk", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("www.google.com.eg", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("google.com.eg", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("encrypted.google.com", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("search.google.com", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("images.google.com", StringComparison.OrdinalIgnoreCase) ||
               domain.Equals("lens.google.com", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsWhitelisted(string domain)
    {
        var whitelist = _getWhitelist();

        if (whitelist.Contains(domain)) return true;
        foreach (var allowed in whitelist)
        {
            if (domain.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        lock (_dynamicEntries)
        {
            if (_dynamicEntries.Contains(domain)) return true;
            foreach (var allowed in _dynamicEntries)
            {
                if (domain.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }
}