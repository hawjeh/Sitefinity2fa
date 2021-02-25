using SitefinityWebApp.Services;
using System;
using Telerik.Sitefinity.Abstractions;
using Telerik.Sitefinity.Security.Events;
using Telerik.Sitefinity.Services;

namespace SitefinityWebApp
{
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            // Sitefinity is ready
            Bootstrapper.Bootstrapped += Bootstrapper_Bootstrapped;
        }

        private void Bootstrapper_Bootstrapped(object sender, EventArgs e)
        {
            EventHub.Subscribe<UserCreated>(evt => UserCreatedEventHandler(evt)); // User Created
        }

        public void UserCreatedEventHandler(UserCreated eventInfo)
        {
            var userService = new WsUserService();
            userService.AssignAuthCodeToUser(eventInfo.UserId);
        }
    }
}