using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace LastAuthentication.Service;

internal class Program
{
    static void Main(string[] args)
    {
        HostApplicationBuilder builder =
            Host.CreateApplicationBuilder(args);

        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName =
                "LastAuthentication Service";
        });

        builder.Services.AddSingleton<LoginStorage>();

        builder.Services.AddSingleton<SecurityLogMonitor>();

        builder.Services.AddSingleton<
            AuthenticationPipeServer>();

        builder.Services.AddHostedService<
            AuthenticationService>();

        builder.Services.AddHostedService<
            PipeHostedService>();

        IHost host =
            builder.Build();

        host.Run();
    }
}