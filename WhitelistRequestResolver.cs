namespace TimeLockService;

using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using DNS.Server;
using System.Net;

public class WhitelistRequestResolver : IRequestResolver
{
    private readonly HashSet<string> _whitelist;

    public WhitelistRequestResolver(HashSet<string> whitelist)
    {
        _whitelist = whitelist;
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

                try
                {
                    var client = new DnsClient("1.1.1.1");
                    var task = client.Resolve(domain, question.Type);
                    var completed = await Task.WhenAny(task, Task.Delay(5000));

                    if (completed == task && task.IsCompletedSuccessfully)
                    {
                        foreach (var answer in task.Result.AnswerRecords)
                        {
                            ((Response)response).AnswerRecords.Add(answer);
                        }
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
        if (_whitelist.Contains(domain)) return true;

        foreach (var allowed in _whitelist)
        {
            if (domain.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}