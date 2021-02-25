using System;
using Telerik.Sitefinity.Data;
using Telerik.Sitefinity.Model;
using Telerik.Sitefinity.Security;
using Telerik.Sitefinity.Security.Model;

namespace SitefinityWebApp.Services
{
    public class WsUserService
    {
        private readonly UserManager _userManager;
        private readonly UserProfileManager _userProfileManager;
        private readonly string UserServiceTransactionName = "UserService12345";
        private readonly string UserProfileServiceTransactionName = "UserProfileService12345";

        public WsUserService()
        {
            _userManager = UserManager.GetManager(string.Empty, UserServiceTransactionName);
            _userProfileManager = UserProfileManager.GetManager(string.Empty, UserProfileServiceTransactionName);
        }

        public void AssignAuthCodeToUser(Guid userId)
        {
            try
            {
                var user = _userManager.GetUser(userId);
                if (user != null)
                {
                    var userProfile = _userProfileManager.GetUserProfile<SitefinityProfile>(user);
                    if (userProfile != null)
                    {
                        var authCode = WsAuthService.GenerateEncodedSecret();
                        _userProfileManager.Provider.SuppressSecurityChecks = true;
                        userProfile.SetValue("AuthCode", authCode);
                        TransactionManager.CommitTransaction(UserProfileServiceTransactionName);
                        _userProfileManager.Provider.SuppressSecurityChecks = false;

                        WsEmailService.PrepareUserTwoFaQrEmail(user.Email, authCode);
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public bool ValidateUser(string username, string password)
        {
            return _userManager.ValidateUser(username, password);
        }

        public string GetUserAuthCode(string username)
        {
            try
            {
                var user = _userManager.GetUser(username);
                if (user != null)
                {
                    var userProfile = _userProfileManager.GetUserProfile<SitefinityProfile>(user);
                    if (userProfile != null)
                    {
                        return userProfile.GetValue<string>("AuthCode");
                    }
                }
            }
            catch (Exception)
            {

            }

            return string.Empty;
        }
    }
}