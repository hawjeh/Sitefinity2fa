using System;
using System.Collections.Generic;
using System.Net.Mail;
using Telerik.Sitefinity.Services;
using Telerik.Sitefinity.Services.Notifications;
using Telerik.Sitefinity.Services.Notifications.Configuration;

namespace SitefinityWebApp.Services
{
    public class WsEmailService
    {
        public static void PrepareUserTwoFaQrEmail(string userEmail, string authCode)
        {
            try
            {
                var emailList = new List<MailMessage>();
                var context = new ServiceContext(string.Empty, "UserTwoFaQrCode");
                var profile = SystemManager.GetNotificationService().GetDefaultSenderProfile(context, "smtp");
                var sender = profile.CustomProperties["defaultSenderEmailAddress"];
                var provisionUrl = string.Format("otpauth://totp/{0}?secret={1}", userEmail.Substring(0, userEmail.IndexOf("@")), authCode);
                var qrCodeUrl = string.Format("http://chart.apis.google.com/chart?cht=qr&chs={0}x{1}&chl={2}", 270, 270, provisionUrl);

                var message = new MailMessage
                {
                    From = new MailAddress(sender, sender),
                    Subject = "User 2FA QR Code",
                    Body = string.Format("Hello, <br/><br/>your 2FA Key: {0}<br/><br><img src='{1}' alt='QR Code'/>", authCode, qrCodeUrl),
                    IsBodyHtml = true
                };

                message.To.Add(userEmail);
                emailList.Add(message);
                SendEmail(profile, emailList);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static void SendEmail(ISenderProfile profile, List<MailMessage> messages)
        {
            try
            {
                // Sending Email

                var smtpServer = new SmtpClient
                {
                    Host = profile.CustomProperties["host"],
                    Port = Convert.ToInt32(profile.CustomProperties["port"]),
                    EnableSsl = Convert.ToBoolean(profile.CustomProperties["useSSL"]),
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    Credentials = new System.Net.NetworkCredential(profile.CustomProperties["username"], profile.CustomProperties["password"])
                };

                foreach (var message in messages)
                {
                    smtpServer.Send(message);
                }

                // Finish Sending Email
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}