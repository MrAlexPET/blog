if (old != null)
{
    bool sameType =
        old.CurrentLogonType ==
        currentLogonType;

    TimeSpan difference =
        currentLogin -
        old.CurrentLogin;

    if (sameType &&
        difference >= TimeSpan.Zero &&
        difference <= TimeSpan.FromSeconds(5))
    {
        return;
    }
}