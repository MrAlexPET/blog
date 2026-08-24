private void OnLoginDetected(LoginEvent login)
{
    try
    {
        // Нас интересуют только интерактивные входы:
        // 10 = RDP
        // 11 = CachedInteractive
        //
        // 3, 7 и остальные события игнорируем.
        if (login.LogonType != 10 &&
            login.LogonType != 11)
        {
            return;
        }

        LoginHistory? previous =
            _storage.Get(login.TargetUserSid);

        /*
         * Windows может создать несколько событий 4624
         * для одного фактического входа.
         *
         * Например:
         *
         * 09:49:44.615 Type 11
         * 09:49:44.615 Type 11
         *
         * Поэтому одинаковые входы, произошедшие
         * практически одновременно, считаем одним входом.
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
                    "SID={Sid}, Type={Type}, Time={Time}",
                    login.TargetUserSid,
                    login.LogonType,
                    login.Time);

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
    }
    catch (Exception ex)
    {
        _logger.LogError(
            ex,
            "Error processing login.");
    }
}