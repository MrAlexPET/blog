private static string? GetClientSid(
    NamedPipeServerStream pipe)
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

        return sid;
    }
    catch
    {
        return null;
    }
}