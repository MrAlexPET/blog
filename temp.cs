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
            try
            {
                var pipe =
                    new NamedPipeServerStream(
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
                break;
            }
            catch (Exception ex)
            {
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
                string? sid =
                    GetClientSid(pipe);

                if (string.IsNullOrEmpty(sid))
                {
                    _logger.LogWarning(
                        "Unable to determine client SID.");

                    return;
                }

                _logger.LogInformation(
                    "Pipe client connected. SID={Sid}",
                    sid);

                LoginHistory? history =
                    _storage.Get(sid);

                if (history == null)
                {
                    await SendResponseAsync(
                        pipe,
                        null,
                        cancellationToken);

                    return;
                }

                await SendResponseAsync(
                    pipe,
                    history,
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Error handling pipe client.");
            }
        }
    }

    private static string? GetClientSid(
        NamedPipeServerStream pipe)
    {
        try
        {
            WindowsIdentity identity =
                pipe.GetImpersonationUserName() != null
                    ? WindowsIdentity.GetCurrent(
                        TokenAccessLevels.Query)
                    : WindowsIdentity.GetCurrent();

            using (identity)
            {
                return identity.User?.Value;
            }
        }
        catch
        {
            return null;
        }
    }

    private static async Task SendResponseAsync(
        NamedPipeServerStream pipe,
        LoginHistory? history,
        CancellationToken cancellationToken)
    {
        var response = new PipeResponse
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