using System;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
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
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                string sid = identity.User?.Value ?? "";
                string username = identity.Name;

                if (string.IsNullOrEmpty(sid))
                {
                    MessageBox.Show(
                        "Не удалось определить SID текущего пользователя.",
                        "Last Authentication",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );

                    return;
                }

                DateTime? previousLogin =
                    FindPreviousAuthentication(sid);

                // Временная диагностика
                MessageBox.Show(
                    $"Пользователь: {username}\n\n" +
                    $"SID:\n{sid}\n\n" +
                    $"Предыдущая аутентификация:\n" +
                    (
                        previousLogin.HasValue
                            ? previousLogin.Value.ToString(
                                "dd.MM.yyyy HH:mm:ss")
                            : "НЕ НАЙДЕНО"
                    ),
                    "DEBUG",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                if (previousLogin.HasValue)
                {
                    ShowLastAuthentication(
                        username,
                        previousLogin.Value
                    );
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Произошла ошибка:\n\n" +
                    ex,
                    "Last Authentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        private DateTime? FindPreviousAuthentication(string currentSid)
        {
            try
            {
                /*
                 * Получаем последние события 4624.
                 *
                 * Здесь намеренно НЕ фильтруем SID через XPath.
                 * Мы будем самостоятельно разбирать каждое событие.
                 */

                string query = @"
                    <QueryList>
                        <Query Id=""0"" Path=""Security"">
                            <Select Path=""Security"">
                                *[System[EventID=4624]]
                            </Select>
                        </Query>
                    </QueryList>";

                EventLogQuery eventQuery = new EventLogQuery(
                    "Security",
                    PathType.LogName,
                    query
                )
                {
                    ReverseDirection = true
                };

                using EventLogReader reader =
                    new EventLogReader(eventQuery);

                EventRecord? eventRecord;

                DateTime programStart = DateTime.Now;

                bool currentLoginFound = false;

                while ((eventRecord = reader.ReadEvent()) != null)
                {
                    try
                    {
                        if (!eventRecord.TimeCreated.HasValue)
                            continue;

                        string xml = eventRecord.ToXml();

                        AuthenticationEventInfo info =
                            ParseAuthenticationEvent(xml);

                        /*
                         * Нас интересуют только:
                         *
                         * LogonType 2  = обычный вход
                         * LogonType 10 = RDP
                         */

                        if (info.LogonType != 2 &&
                            info.LogonType != 10)
                        {
                            continue;
                        }

                        /*
                         * Проверяем SID пользователя.
                         */

                        if (!string.Equals(
                            info.TargetUserSid,
                            currentSid,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        DateTime eventTime =
                            eventRecord.TimeCreated.Value;

                        /*
                         * Если самое новое событие произошло
                         * совсем недавно, считаем его текущим
                         * входом.
                         */

                        TimeSpan difference =
                            programStart - eventTime;

                        if (!currentLoginFound &&
                            difference.TotalSeconds >= 0 &&
                            difference.TotalSeconds <= 120)
                        {
                            currentLoginFound = true;
                            continue;
                        }

                        /*
                         * Следующее подходящее событие —
                         * предыдущая аутентификация.
                         */

                        return eventTime;
                    }
                    finally
                    {
                        eventRecord.Dispose();
                    }
                }

                return null;
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(
                    "Нет доступа к журналу Security.\n\n" +
                    "Запустите VS Code или PowerShell " +
                    "от имени администратора.",
                    "Last Authentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );

                return null;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Ошибка чтения журнала Security:\n\n" +
                    ex,
                    "Last Authentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );

                return null;
            }
        }

        private AuthenticationEventInfo ParseAuthenticationEvent(
            string xml)
        {
            AuthenticationEventInfo result =
                new AuthenticationEventInfo();

            try
            {
                XDocument document =
                    XDocument.Parse(xml);

                XNamespace ns =
                    "http://schemas.microsoft.com/win/2004/08/events/event";

                foreach (XElement data
                    in document.Descendants(ns + "Data"))
                {
                    string? name =
                        data.Attribute("Name")?.Value;

                    string value =
                        data.Value;

                    if (name == "TargetUserSid")
                    {
                        result.TargetUserSid = value;
                    }
                    else if (name == "TargetUserName")
                    {
                        result.TargetUserName = value;
                    }
                    else if (name == "TargetDomainName")
                    {
                        result.TargetDomainName = value;
                    }
                    else if (name == "LogonType")
                    {
                        int.TryParse(
                            value,
                            out result.LogonType
                        );
                    }
                    else if (name == "TargetLogonId")
                    {
                        result.TargetLogonId = value;
                    }
                }
            }
            catch
            {
                // Если событие невозможно разобрать,
                // возвращаем пустой результат.
            }

            return result;
        }

        private void ShowLastAuthentication(
            string username,
            DateTime authenticationTime)
        {
            MessageBox.Show(
                $"Пользователь:\n" +
                $"{username}\n\n" +

                $"Последняя успешная " +
                $"аутентификация:\n" +

                $"{authenticationTime:dd.MM.yyyy HH:mm:ss}",

                "Последняя аутентификация",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );
        }
    }

    public class AuthenticationEventInfo
    {
        public string TargetUserSid { get; set; } = "";

        public string TargetUserName { get; set; } = "";

        public string TargetDomainName { get; set; } = "";

        public string TargetLogonId { get; set; } = "";

        public int LogonType { get; set; } = -1;
    }
}