using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LastAuthentication.Service;

public class AuthenticationPipeServer
{
    private const string PipeName = "LastAuthentication";

    private readonly LoginStorage _storage;
    private readonly ILogger<AuthenticationPipeServer> _logger;

    public AuthenticationPipeServer(
        LoginStorage storage,
        ILogger<AuthenticationPipeServer> logger)
    {
        _storage = storage;
        _logger = logger;
    }

    public async Task StartAsync(
        CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "Authentication Pipe Server started.");

        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(
                    cancellationToken);

                _ = HandleClientAsync(
                    pipe,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();

                _logger.LogError(
                    ex,
                    "Error in Named Pipe server.");

                await Task.Delay(
                    1000,
                    cancellationToken);
            }
        }
    }

    private async Task HandleClientAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        using (pipe)
        {
            try
            {
                string? sid = null;

                pipe.RunAsClient(() =>
                {
                    using WindowsIdentity identity =
                        WindowsIdentity.GetCurrent();

                    sid = identity.User?.Value;
                });

                if (string.IsNullOrWhiteSpace(sid))
                {
                    _logger.LogWarning(
                        "Could not determine client SID.");

                    await SendResponseAsync(
                        pipe,
                        null,
                        cancellationToken);

                    return;
                }

                _logger.LogInformation(
                    "Pipe client SID: {Sid}",
                    sid);

                LoginHistory? history =
                    _storage.Get(sid);

                if (history == null)
                {
                    _logger.LogInformation(
                        "No login history found for SID {Sid}",
                        sid);

                    await SendResponseAsync(
                        pipe,
                        null,
                        cancellationToken);

                    return;
                }

                _logger.LogInformation(
                    "Sending previous login {Time} for SID {Sid}",
                    history.PreviousLogin,
                    sid);

                await SendResponseAsync(
                    pipe,
                    history,
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error handling Named Pipe client.");
            }
        }
    }

    private static async Task SendResponseAsync(
        NamedPipeServerStream pipe,
        LoginHistory? history,
        CancellationToken cancellationToken)
    {
        PipeResponse response = new()
        {
            Success =
                history?.PreviousLogin != null,

            PreviousLogin =
                history?.PreviousLogin,

            PreviousLogonType =
                history?.PreviousLogonType
        };

        string json =
            JsonSerializer.Serialize(response);

        byte[] data =
            Encoding.UTF8.GetBytes(json);

        await pipe.WriteAsync(
            data,
            cancellationToken);

        await pipe.FlushAsync(
            cancellationToken);
    }
}

public class PipeResponse
{
    public bool Success { get; set; }

    public DateTime? PreviousLogin { get; set; }

    public int? PreviousLogonType { get; set; }
}