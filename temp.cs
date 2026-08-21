using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace LastAuthentication.Service;

public class SecurityLogMonitor
{
    public event Action<LoginEvent>? LoginDetected;

    private EventLogWatcher? _watcher;

    public void Start()
    {
        string query = @"
<QueryList>
    <Query Id=""0"" Path=""Security"">
        <Select Path=""Security"">
            *[System[(EventID=4624)]]
        </Select>
    </Query>
</QueryList>";

        EventLogQuery eventQuery =
            new EventLogQuery(
                "Security",
                PathType.LogName,
                query);

        _watcher =
            new EventLogWatcher(eventQuery);

        _watcher.EventRecordWritten +=
            OnEventRecordWritten;

        _watcher.Enabled = true;
    }

    public void Stop()
    {
        if (_watcher == null)
            return;

        _watcher.Enabled = false;

        _watcher.EventRecordWritten -=
            OnEventRecordWritten;

        _watcher.Dispose();

        _watcher = null;
    }

    private void OnEventRecordWritten(
        object? sender,
        EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null)
            return;

        try
        {
            string xml =
                e.EventRecord.ToXml();

            LoginEvent? login =
                ParseEvent(xml);

            if (login == null)
                return;

            /*
             * Нас интересуют только
             * интерактивные входы.
             */
            if (!IsInterestingLogonType(
                    login.LogonType))
            {
                return;
            }

            LoginDetected?.Invoke(login);
        }
        catch
        {
        }
        finally
        {
            e.EventRecord.Dispose();
        }
    }

    private bool IsInterestingLogonType(
        int logonType)
    {
        return
            logonType == 2 ||
            logonType == 10 ||
            logonType == 11 ||
            logonType == 12;
    }

    private LoginEvent? ParseEvent(
        string xml)
    {
        try
        {
            XDocument document =
                XDocument.Parse(xml);

            XNamespace ns =
                "http://schemas.microsoft.com/win/2004/08/events/event";

            LoginEvent result =
                new LoginEvent();

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

                    case "TargetUserName":
                        result.TargetUserName =
                            value;
                        break;

                    case "TargetDomainName":
                        result.TargetDomain =
                            value;
                        break;

                    case "TargetLogonId":
                        result.LogonId =
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

            if (string.IsNullOrEmpty(
                    result.TargetUserSid))
            {
                return null;
            }

            if (result.LogonType < 0)
            {
                return null;
            }

            return result;
        }
        catch
        {
            return null;
        }
    }
}

public class LoginEvent
{
    public string TargetUserSid { get; set; } = "";

    public string TargetUserName { get; set; } = "";

    public string TargetDomain { get; set; } = "";

    public string LogonId { get; set; } = "";

    public int LogonType { get; set; }

    public DateTime Time { get; set; } =
        DateTime.Now;
}