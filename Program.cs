using TimeLockService;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;

var builder = Host.CreateApplicationBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "TimeLockService";
});

builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<DnsWhitelistService>();

var host = builder.Build();
host.Run();