using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LastAuthentication.Service;

public class AuthenticationService : BackgroundService
{
    private readonly SecurityLogMonitor _monitor;

    private readonly LoginStorage _storage;

    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        SecurityLogMonitor monitor,
        LoginStorage storage,
        ILogger<AuthenticationService> logger)
    {
        _monitor = monitor;
        _storage = storage;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _monitor.LoginDetected +=
            OnLoginDetected;

        _monitor.Start();

        _logger.LogInformation(
            "LastAuthentication Service started.");

        try
        {
            await Task.Delay(
                Timeout.Infinite,
                stoppingToken);
        }
        catch (TaskCanceledException)
        {
        }
        finally
        {
            _monitor.Stop();

            _monitor.LoginDetected -=
                OnLoginDetected;
        }
    }

    private void OnLoginDetected(
        LoginEvent login)
    {
        try
        {
            StoredLogin? previous =
                _storage.Get(
                    login.TargetUserSid);

            /*
             * Одна и та же logon-сессия
             * может породить несколько связанных
             * событий. Повторно её не сохраняем.
             */
            if (previous != null &&
                !string.IsNullOrEmpty(
                    previous.LogonId) &&
                string.Equals(
                    previous.LogonId,
                    login.LogonId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _logger.LogInformation(
                "Login detected: {User}, " +
                "Type={Type}, " +
                "Time={Time}, " +
                "LogonId={LogonId}",
                login.TargetUserName,
                login.LogonType,
                login.Time,
                login.LogonId);

            /*
             * Сохраняем текущий вход.
             */
            _storage.Save(
                login.TargetUserSid,
                login.Time,
                login.LogonType,
                login.LogonId);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error processing login.");
        }
    }
}