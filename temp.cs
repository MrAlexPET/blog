private async void OnLoginDetected(LoginEvent login)
{
    try
    {
        if (login.LogonType != 10 &&
            login.LogonType != 11)
        {
            return;
        }

        LoginHistory? previous =
            _storage.Get(login.TargetUserSid);

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

        _logger.LogInformation(
            "New login detected. " +
            "User={User}, SID={Sid}, Type={Type}, Time={Time}, LogonId={LogonId}",
            login.TargetUserName,
            login.TargetUserSid,
            login.LogonType,
            login.Time,
            login.LogonId);

        _storage.Save(
            login.TargetUserSid,
            login.Time,
            login.LogonType,
            login.LogonId);

        /*
         * После входа Windows ещё некоторое время
         * может создавать пользовательскую сессию.
         *
         * Поэтому НЕ пытаемся запускать UI мгновенно.
         */
        _logger.LogInformation(
            "Waiting for interactive session to become ready...");

        await Task.Delay(3000);

        /*
         * Несколько попыток запуска.
         *
         * Это особенно важно после перезагрузки,
         * когда 4624 может появиться раньше,
         * чем WTSQueryUserToken сможет получить
         * пользовательский token.
         */
        for (int attempt = 1; attempt <= 5; attempt++)
        {
            _logger.LogInformation(
                "UI launch attempt {Attempt}/5",
                attempt);

            bool launched = LaunchUserInterface();

            if (launched)
            {
                _logger.LogInformation(
                    "UI successfully launched on attempt {Attempt}.",
                    attempt);

                return;
            }

            if (attempt < 5)
            {
                await Task.Delay(2000);
            }
        }

        _logger.LogError(
            "Failed to launch UI after 5 attempts.");
    }
    catch (Exception ex)
    {
        _logger.LogError(
            ex,
            "Error processing login event.");
    }
}