using System;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using System.Xml.Linq;

namespace LastAuthentication
{
    public enum LoginType
    {
        Unknown,
        Local,
        Rdp
    }

    public class LoginInfo
    {
        public DateTime Time { get; set; }

        public LoginType Type { get; set; }

        public int LogonType { get; set; }

        public string LogonId { get; set; } = "";
    }

    public class LoginDetector
    {
        public LoginInfo? FindCurrentLogin()
        {
            WindowsIdentity identity =
                WindowsIdentity.GetCurrent();

            string sid =
                identity.User?.Value ?? "";

            if (string.IsNullOrEmpty(sid))
                return null;

            string query = @"
                <QueryList>
                    <Query Id=""0"" Path=""Security"">
                        <Select Path=""Security"">
                            *[System[EventID=4624]]
                        </Select>
                    </Query>
                </QueryList>";

            EventLogQuery eventQuery =
                new EventLogQuery(
                    "Security",
                    PathType.LogName,
                    query
                )
                {
                    ReverseDirection = true
                };

            using EventLogReader reader =
                new EventLogReader(eventQuery);

            EventRecord? record;

            int checkedEvents = 0;

            while (
                (record = reader.ReadEvent()) != null &&
                checkedEvents < 200)
            {
                try
                {
                    checkedEvents++;

                    if (!record.TimeCreated.HasValue)
                        continue;

                    AuthenticationEventInfo info =
                        ParseEvent(record.ToXml());

                    if (!string.Equals(
                        info.TargetUserSid,
                        sid,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    LoginType? loginType =
                        ConvertLogonType(
                            info.LogonType
                        );

                    if (!loginType.HasValue)
                        continue;

                    return new LoginInfo
                    {
                        Time =
                            record.TimeCreated.Value,

                        Type =
                            loginType.Value,

                        LogonType =
                            info.LogonType,

                        LogonId =
                            info.TargetLogonId
                    };
                }
                finally
                {
                    record.Dispose();
                }
            }

            return null;
        }

        private LoginType? ConvertLogonType(
            int logonType)
        {
            switch (logonType)
            {
                // Interactive
                case 2:

                    return LoginType.Local;

                // RemoteInteractive
                case 10:

                    return LoginType.Rdp;

                // CachedInteractive
                case 11:

                    return LoginType.Local;

                // CachedRemoteInteractive
                case 12:

                    return LoginType.Rdp;

                default:

                    return null;
            }
        }

        private AuthenticationEventInfo
            ParseEvent(string xml)
        {
            AuthenticationEventInfo result =
                new AuthenticationEventInfo();

            try
            {
                XDocument document =
                    XDocument.Parse(xml);

                XNamespace ns =
                    "http://schemas.microsoft.com/win/2004/08/events/event";

                foreach (
                    XElement data
                    in document.Descendants(ns + "Data"))
                {
                    string? name =
                        data.Attribute("Name")?.Value;

                    string value =
                        data.Value;

                    switch (name)
                    {
                        case "TargetUserSid":

                            result.TargetUserSid =
                                value;

                            break;

                        case "TargetLogonId":

                            result.TargetLogonId =
                                value;

                            break;

                        case "LogonType":

                            if (int.TryParse(
                                value,
                                out int type))
                            {
                                result.LogonType =
                                    type;
                            }

                            break;
                    }
                }
            }
            catch
            {
            }

            return result;
        }

        private class AuthenticationEventInfo
        {
            public string TargetUserSid { get; set; } = "";

            public string TargetLogonId { get; set; } = "";

            public int LogonType { get; set; } = -1;
        }
    }
}