try
{
    if (File.Exists(_uiPath))
    {
        bool launched =
            SessionProcessLauncher.LaunchForActiveUser(
                _uiPath);

        _logger.LogInformation(
            "UI launch result: {Result}",
            launched);
    }
    else
    {
        _logger.LogWarning(
            "UI executable not found: {Path}",
            _uiPath);
    }
}
catch (Exception ex)
{
    _logger.LogError(
        ex,
        "Failed to launch UI.");
}