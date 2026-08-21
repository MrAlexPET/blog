using System;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using System.Windows.Forms;

namespace LastAuthentication
{
    public class AuthenticationManager
    {
        public void ProcessLogin()
        {
            try
            {
                WindowsIdentity identity =
                    WindowsIdentity.GetCurrent();

                string username = identity.Name;
                string sid = identity.User?.Value ?? "UNKNOWN";

                int sessionId =
                    GetCurrentSessionId();

                StringBuilder report =
                    new StringBuilder();

                report.AppendLine(
                    "===== CURRENT USER ====="
                );

                report.AppendLine(
                    $"Username: {username}"
                );

                report.AppendLine(
                    $"SID: {sid}"
                );

                report.AppendLine(
                    $"Session ID: {sessionId}"
                );

                report.AppendLine();

                report.AppendLine(
                    "===== SECURITY 4624 ====="
                );

                report.AppendLine();

                ReadSecurityEvents(
                    sid,
                    report
                );

                report.AppendLine();

                report.AppendLine(
                    "===== RDP SESSION EVENTS ====="
                );

                report.AppendLine();

                ReadRdpEvents(
                    username,
                    report
                );

                ShowReport(report.ToString());
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Ошибка:\n\n" + ex,
                    "Last Authentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        private int GetCurrentSessionId()
        {
            try
            {
                return System.Diagnostics.Process
                    .GetCurrentProcess()
                    .SessionId;
            }
            catch
            {
                return -1;
            }
        }

        private void ReadSecurityEvents(
            string currentSid,
            StringBuilder report)
        {
            try
            {
                string query = @"
                    <QueryList>
                        <Query Id=""0"" Path=""Security"">
                            <Select Path=""Security"">
                                *[System[EventID=4624]]
                            </Select>
                        </Query>
                    </QueryList>";

                EventLogQuery queryObject =
                    new EventLogQuery(
                        "Security",
                        PathType.LogName,
                        query
                    )
                    {
                        ReverseDirection = true
                    };

                using EventLogReader reader =
                    new EventLogReader(queryObject);

                EventRecord? record;

                int counter = 0;

                while (
                    (record = reader.ReadEvent()) != null &&
                    counter < 30)
                {
                    try
                    {
                        if (!record.TimeCreated.HasValue)
                            continue;

                        string xml =
                            record.ToXml();

                        AuthenticationEventInfo info =
                            ParseAuthenticationEvent(xml);

                        if (!string.Equals(
                            info.TargetUserSid,
                            currentSid,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        counter++;

                        report.AppendLine(
                            $"#{counter}"
                        );

                        report.AppendLine(
                            $"Time: {record.TimeCreated:dd.MM.yyyy HH:mm:ss.fff}"
                        );

                        report.AppendLine(
                            $"Record ID: {record.RecordId}"
                        );

                        report.AppendLine(
                            $"Logon Type: {info.LogonType}"
                        );

                        report.AppendLine(
                            $"Target User: {info.TargetUserName}"
                        );

                        report.AppendLine(
                            $"Target Domain: {info.TargetDomainName}"
                        );

                        report.AppendLine(
                            $"Target Logon ID: {info.TargetLogonId}"
                        );

                        report.AppendLine(
                            $"Linked Logon ID: {info.LinkedLogonId}"
                        );

                        report.AppendLine(
                            $"Authentication Package: {info.AuthenticationPackage}"
                        );

                        report.AppendLine(
                            $"Logon Process: {info.LogonProcess}"
                        );

                        report.AppendLine(
                            "----------------------------------------"
                        );
                    }
                    finally
                    {
                        record.Dispose();
                    }
                }

                if (counter == 0)
                {
                    report.AppendLine(
                        "События 4624 для текущего SID не найдены."
                    );
                }
            }
            catch (UnauthorizedAccessException)
            {
                report.AppendLine(
                    "НЕТ ДОСТУПА К SECURITY LOG."
                );

                report.AppendLine(
                    "Запусти программу от имени администратора."
                );
            }
            catch (Exception ex)
            {
                report.AppendLine(
                    "Ошибка чтения Security Log:"
                );

                report.AppendLine(
                    ex.Message
                );
            }
        }

        private void ReadRdpEvents(
            string username,
            StringBuilder report)
        {
            try
            {
                string logName =
                    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

                string query = @"
                    <QueryList>
                        <Query Id=""0"">
                            <Select Path=""Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"">
                                *
                            </Select>
                        </Query>
                    </QueryList>";

                EventLogQuery queryObject =
                    new EventLogQuery(
                        logName,
                        PathType.LogName,
                        query
                    )
                    {
                        ReverseDirection = true
                    };

                using EventLogReader reader =
                    new EventLogReader(queryObject);

                EventRecord? record;

                int counter = 0;

                while (
                    (record = reader.ReadEvent()) != null &&
                    counter < 30)
                {
                    try
                    {
                        if (!record.TimeCreated.HasValue)
                            continue;

                        /*
                         * Для диагностики показываем события:
                         *
                         * 21 = Session logon succeeded
                         * 22 = Shell start
                         * 23 = Session logoff
                         * 24 = Session disconnected
                         * 25 = Session reconnected
                         *
                         * Пока также покажем другие события,
                         * чтобы увидеть, что именно пишет твоя Windows.
                         */

                        counter++;

                        report.AppendLine(
                            $"#{counter}"
                        );

                        report.AppendLine(
                            $"Time: {record.TimeCreated:dd.MM.yyyy HH:mm:ss.fff}"
                        );

                        report.AppendLine(
                            $"Event ID: {record.Id}"
                        );

                        report.AppendLine(
                            $"Record ID: {record.RecordId}"
                        );

                        report.AppendLine(
                            $"Provider: {record.ProviderName}"
                        );

                        string xml =
                            record.ToXml();

                        string? user =
                            GetEventDataValue(
                                xml,
                                "UserName"
                            );

                        string? domain =
                            GetEventDataValue(
                                xml,
                                "DomainName"
                            );

                        string? sessionId =
                            GetEventDataValue(
                                xml,
                                "SessionID"
                            );

                        if (!string.IsNullOrEmpty(user))
                        {
                            report.AppendLine(
                                $"UserName: {user}"
                            );
                        }

                        if (!string.IsNullOrEmpty(domain))
                        {
                            report.AppendLine(
                                $"DomainName: {domain}"
                            );
                        }

                        if (!string.IsNullOrEmpty(sessionId))
                        {
                            report.AppendLine(
                                $"SessionID: {sessionId}"
                            );
                        }

                        report.AppendLine(
                            "----------------------------------------"
                        );
                    }
                    finally
                    {
                        record.Dispose();
                    }
                }

                if (counter == 0)
                {
                    report.AppendLine(
                        "RDP events not found."
                    );
                }
            }
            catch (Exception ex)
            {
                report.AppendLine(
                    "Ошибка чтения RDP Log:"
                );

                report.AppendLine(
                    ex.Message
                );
            }
        }

        private AuthenticationEventInfo
            ParseAuthenticationEvent(string xml)
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

                        case "TargetUserName":

                            result.TargetUserName =
                                value;

                            break;

                        case "TargetDomainName":

                            result.TargetDomainName =
                                value;

                            break;

                        case "LogonType":

                            if (int.TryParse(
                                value,
                                out int logonType))
                            {
                                result.LogonType =
                                    logonType;
                            }

                            break;

                        case "TargetLogonId":

                            result.TargetLogonId =
                                value;

                            break;

                        case "LinkedLogonId":

                            result.LinkedLogonId =
                                value;

                            break;

                        case "AuthenticationPackageName":

                            result.AuthenticationPackage =
                                value;

                            break;

                        case "LogonProcessName":

                            result.LogonProcess =
                                value;

                            break;
                    }
                }
            }
            catch
            {
                // Оставляем пустые значения.
            }

            return result;
        }

        private string? GetEventDataValue(
            string xml,
            string dataName)
        {
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

                    if (string.Equals(
                        name,
                        dataName,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return data.Value;
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private void ShowReport(string report)
        {
            Form form = new Form();

            form.Text =
                "Last Authentication - Diagnostics";

            form.Width = 900;
            form.Height = 700;

            TextBox textBox =
                new TextBox();

            textBox.Multiline = true;
            textBox.ReadOnly = true;
            textBox.ScrollBars =
                ScrollBars.Both;

            textBox.Dock =
                DockStyle.Fill;

            textBox.Font =
                new System.Drawing.Font(
                    "Consolas",
                    10
                );

            textBox.Text =
                report;

            form.Controls.Add(
                textBox
            );

            form.ShowDialog();
        }
    }

    public class AuthenticationEventInfo
    {
        public string TargetUserSid { get; set; } = "";

        public string TargetUserName { get; set; } = "";

        public string TargetDomainName { get; set; } = "";

        public string TargetLogonId { get; set; } = "";

        public string LinkedLogonId { get; set; } = "";

        public string AuthenticationPackage { get; set; } = "";

        public string LogonProcess { get; set; } = "";

        public int LogonType { get; set; } = -1;
    }
}