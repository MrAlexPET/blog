using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LastAuthentication.Service;

public class AuthenticationService : BackgroundService
{
    private readonly SecurityLogMonitor _monitor;
    private readonly LoginStorage _storage;
    private readonly ILogger<AuthenticationService> _logger;

    private readonly string _uiPath;

    public AuthenticationService(
        SecurityLogMonitor monitor,
        LoginStorage storage,
        ILogger<AuthenticationService> logger)
    {
        _monitor = monitor;
        _storage = storage;
        _logger = logger;

        _uiPath = Path.Combine(
            AppContext.BaseDirectory,
            "LastAuthentication.UI.exe");
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _monitor.LoginDetected += OnLoginDetected;

        _monitor.Start();

        _logger.LogInformation(
            "LastAuthentication Service started.");

        _logger.LogInformation(
            "UI path: {Path}",
            _uiPath);

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

            _monitor.LoginDetected -= OnLoginDetected;
        }
    }

    private void OnLoginDetected(LoginEvent login)
    {
        try
        {
            /*
             * Нас интересуют только интерактивные
             * способы успешной аутентификации:
             *
             * 10 = RemoteInteractive (RDP)
             * 11 = CachedInteractive
             *
             * Тип 3, 7 и остальные события
             * игнорируем.
             */
            if (login.LogonType != 10 &&
                login.LogonType != 11)
            {
                return;
            }

            /*
             * Получаем сохранённую информацию
             * по этому пользователю.
             */
            LoginHistory? previous =
                _storage.Get(
                    login.TargetUserSid);

            /*
             * Windows может создать несколько
             * событий 4624 практически одновременно
             * для одного фактического входа.
             *
             * Например:
             *
             * 09:49:44.615 Type 11
             * 09:49:44.615 Type 11
             *
             * Второе событие не является новым входом.
             */
            if (previous != null)
            {
                bool sameType =
                    previous.CurrentLogonType ==
                    login.LogonType;

                TimeSpan difference =
                    login.Time -
                    previous.CurrentLogin;

                if (sameType &&
                    difference >= TimeSpan.Zero &&
                    difference <= TimeSpan.FromSeconds(5))
                {
                    _logger.LogInformation(
                        "Duplicate 4624 ignored. " +
                        "SID={Sid}, Type={Type}, Time={Time}, LogonId={LogonId}",
                        login.TargetUserSid,
                        login.LogonType,
                        login.Time,
                        login.LogonId);

                    return;
                }
            }

            /*
             * Это новый успешный интерактивный вход.
             */
            _logger.LogInformation(
                "New login detected. " +
                "User={User}, SID={Sid}, Type={Type}, Time={Time}, LogonId={LogonId}",
                login.TargetUserName,
                login.TargetUserSid,
                login.LogonType,
                login.Time,
                login.LogonId);

            /*
             * Сохраняем новый вход.
             *
             * LoginStorage автоматически переносит
             * старый CurrentLogin в PreviousLogin.
             */
            _storage.Save(
                login.TargetUserSid,
                login.Time,
                login.LogonType,
                login.LogonId);

            /*
             * После сохранения пытаемся запустить UI.
             */
            LaunchUserInterface();
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Error processing login event.");
        }
    }

    private void LaunchUserInterface()
    {
        try
        {
            /*
             * Проверяем наличие UI рядом с Service.exe.
             */
            if (!File.Exists(_uiPath))
            {
                _logger.LogWarning(
                    "UI executable not found: {Path}",
                    _uiPath);

                return;
            }

            _logger.LogInformation(
                "Attempting to launch UI: {Path}",
                _uiPath);

            /*
             * На текущем этапе запускаем UI
             * в активной локальной пользовательской
             * сессии.
             *
             * Для RDP сделаем отдельную обработку
             * на следующем этапе.
             */
            bool launched =
                SessionProcessLauncher.LaunchForActiveUser(
                    _uiPath);

            _logger.LogInformation(
                "UI launch result: {Result}",
                launched);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to launch LastAuthentication.UI.");
        }
    }
}