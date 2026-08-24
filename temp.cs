using Microsoft.Extensions.Hosting;

namespace LastAuthentication.Service;

public class PipeHostedService : BackgroundService
{
    private readonly AuthenticationPipeServer _server;

    public PipeHostedService(
        AuthenticationPipeServer server)
    {
        _server = server;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await _server.StartAsync(
            stoppingToken);
    }
}