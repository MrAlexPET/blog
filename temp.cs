private bool LaunchUserInterface()
{
    try
    {
        if (!File.Exists(_uiPath))
        {
            _logger.LogWarning(
                "UI executable not found: {Path}",
                _uiPath);

            return false;
        }

        _logger.LogInformation(
            "Attempting to launch UI: {Path}",
            _uiPath);

        bool launched =
            SessionProcessLauncher.LaunchForActiveUser(
                _uiPath);

        _logger.LogInformation(
            "UI launch result: {Result}",
            launched);

        return launched;
    }
    catch (Exception ex)
    {
        _logger.LogError(
            ex,
            "Failed to launch LastAuthentication.UI.");

        return false;
    }
}