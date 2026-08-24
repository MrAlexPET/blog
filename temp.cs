private static NamedPipeServerStream CreatePipe()
{
    var security =
        new PipeSecurity();

    security.AddAccessRule(
        new PipeAccessRule(
            new SecurityIdentifier(
                WellKnownSidType.AuthenticatedUserSid,
                null),
            PipeAccessRights.ReadWrite,
            System.Security.AccessControl.AccessControlType.Allow));

    return NamedPipeServerStreamAcl.Create(
        PipeName,
        PipeDirection.InOut,
        1,
        PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous,
        0,
        0,
        security);
}