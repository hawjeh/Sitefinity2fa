using SitefinityWebApp.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using Telerik.Sitefinity.Security;
using Telerik.Sitefinity.Security.Model;

namespace SitefinityWebApp.Mvc.Controllers
{
    // reference: https://github.com/timw255/timw255.Sitefinity.TwoFactorAuthentication
    // reference: https://www.codeproject.com/Articles/403355/Implementing-Two-Factor-Authentication-in-ASP-NET
    // reference: https://github.com/rickbassham/two-factor
    [RoutePrefix("WsAuth")]
    public class WsAuthController : Controller
    {
        [Route]
        public ActionResult Index()
        {
            return Redirect("/");
        }

        [Route("Authenticate/SWT")]
        [HttpGet]
        public ActionResult SWT(string realm, string redirect_uri, string deflate)
        {
            Session["wsauth.authState"] = 0;
            return View("Login");
        }

        [Route("Authenticate/SWT")]
        [HttpPost]
        public ActionResult SWT(string realm, string redirect_uri, string deflate, string wrap_name, string wrap_password, string sf_domain = "Default", string sf_persistent = "false", string is_form = "false")
        {
            var userService = new WsUserService();

            if (userService.ValidateUser(wrap_name, wrap_password))
            {
                Session["wsauth.username"] = wrap_name;
                Session["wsauth.authState"] = 1;
                Session["wsauth.realm"] = realm;
                Session["wsauth.redirect_uri"] = redirect_uri;
                Session["wsauth.deflate"] = deflate;
                Session["wsauth.wrap_name"] = wrap_name;
                Session["wsauth.sf_persistent"] = sf_persistent;

                var userAuthCode = userService.GetUserAuthCode(wrap_name);
                var useTwoFactor = userAuthCode != string.Empty;
                Session["wsauth.authCode"] = userAuthCode;

                if (is_form == "false")
                {
                    if (useTwoFactor)
                    {
                        return Json(new { url = "/WsAuth/Authenticate/Verify" });
                    }

                    return Json(new { url = GetLoginUri() });
                }
                else
                {
                    if (useTwoFactor)
                    {
                        return Redirect("/WsAuth/Authenticate/Verify");
                    }

                    return Redirect(GetLoginUri());
                }
            }

            ModelState.AddModelError("InvalidCredentials", "Incorrect Username/Password Combination");

            return View("Login");
        }

        [Route("Authenticate/Verify")]
        [HttpGet]
        public ActionResult Verify()
        {
            if (!IsAuthState(1))
            {
                return Redirect("/");
            }

            return View("Verify");
        }

        [Route("Authenticate/Verify")]
        [HttpPost]
        public ActionResult Verify(string token)
        {
            if (!IsAuthState(1))
            {
                return Redirect("/");
            }

            var authCode = Session["wsauth.authCode"].ToString();
            var secret = Encoding.UTF8.GetString(new WsEncoder().Decode(authCode));
            var isValid = WsGenerator.IsValid(secret, token);

            if (isValid)
            {
                var userManager = UserManager.GetManager();
                var user = userManager.GetUserByEmail(Session["wsauth.username"].ToString());
                if (user.IsBackendUser && user.IsLoggedIn)
                {
                    SystemManager.RunWithElevatedPrivilege(_ =>
                    {
                        // SecurityManager.Logout("", user.Id);
                        var userActivityManager = ManagerBase.GetManager("Telerik.Sitefinity.Security.UserActivityManager");
                        var userActivityProvider = userActivityManager.Provider as UserActivityProvider;
                        var userActivity = userActivityProvider.GetUserActivity(user.Id, user.ProviderName);
                        userActivity.IsLoggedIn = false;
                        userActivityManager.SaveChanges();
                    });
                }

                var endpoint = System.Web.HttpContext.Current.Request.Url.AbsoluteUri;
                var hostUrl = endpoint.Replace(System.Web.HttpContext.Current.Request.Url.AbsolutePath, "");
                SecurityManager.SkipAuthenticationAndLogin("", Session["username"].ToString(), true, $"{hostUrl}/Sitefinity", $"{hostUrl}/401");
                return null;
                //return Redirect(GetLoginUri());
            }
            else
            {
                ModelState.AddModelError("InvalidToken", "Incorrect Token");
                return View("Verify");
            }
        }

        private bool IsAuthState(int value)
        {
            if (Session["wsauth.authState"] == null)
            {
                return false;
            }

            int authState = ((int)Session["wsauth.authState"]);

            if (authState == value)
            {
                return true;
            }

            return false;
        }

        private string GetLoginUri()
        {
            Session["wsauth.authState"] = 0;
            string realm = Session["wsauth.realm"].ToString();
            string redirect_uri = Session["wsauth.redirect_uri"].ToString();
            bool deflate = "true".Equals(Session["wsauth.deflate"].ToString(), StringComparison.OrdinalIgnoreCase);
            string wrap_name = Session["wsauth.wrap_name"].ToString();
            string sf_persistent = Session["wsauth.sf_persistent"].ToString();

            Uri u = GetTokenUri(realm, redirect_uri, deflate, wrap_name, sf_persistent);

            return u.AbsoluteUri;
        }

        private Uri GetTokenUri(string realm, string redirect_uri, bool deflate, string wrap_name, string sf_persistent)
        {
            var wsAuthService = new WsAuthService();
            return wsAuthService.ProcessRequest(realm, redirect_uri, deflate, wrap_name, sf_persistent);
        }
    }
}
