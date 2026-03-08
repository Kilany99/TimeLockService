namespace TimeLockService;

using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using DNS.Server;
using System.Net;

public class WhitelistRequestResolver : IRequestResolver
{
    // Func so it always reads the CURRENT active whitelist (strict or full)
    private readonly Func<HashSet<string>> _getWhitelist;
    private readonly HashSet<string> _dynamicEntries;

    public WhitelistRequestResolver(
        Func<HashSet<string>> getWhitelist,
        HashSet<string> dynamicEntries)
    {
        _getWhitelist = getWhitelist;
        _dynamicEntries = dynamicEntries;
    }

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = default)
    {
        IResponse response = Response.FromRequest(request);

        foreach (var question in request.Questions)
        {
            string domain = question.Name.ToString().TrimEnd('.');

            if (IsWhitelisted(domain))
            {
                ServiceLogger.Dns($"✅ ALLOWED: {domain}");
                DnsWhitelistService.IncrementAllowed();

                try
                {
                    var client = new DnsClient("1.1.1.1");
                    var task = client.Resolve(domain, question.Type);
                    var completed = await Task.WhenAny(task, Task.Delay(5000, cancellationToken));

                    if (completed == task && task.IsCompletedSuccessfully)
                    {
                        foreach (var answer in task.Result.AnswerRecords)
                            ((Response)response).AnswerRecords.Add(answer);
                    }
                    else
                    {
                        ServiceLogger.Dns($"⏱️ TIMEOUT: {domain}");
                    }
                }
                catch (Exception ex)
                {
                    ServiceLogger.Dns($"⚠️ Failed: {domain} - {ex.Message}");
                }
            }
            else
            {
                ServiceLogger.Dns($"🚫 BLOCKED: {domain}");
                DnsWhitelistService.IncrementBlocked();

                var record = new IPAddressResourceRecord(
                    question.Name,
                    IPAddress.Any,
                    TimeSpan.FromMinutes(5));

                ((Response)response).AnswerRecords.Add(record);
            }
        }

        return response;
    }

    private bool IsWhitelisted(string domain)
    {
        var whitelist = _getWhitelist();

        // Check static whitelist
        if (whitelist.Contains(domain)) return true;
        foreach (var allowed in whitelist)
        {
            if (domain.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Check dynamic entries (password-added)
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