using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Telerik.Sitefinity.Configuration;
using Telerik.Sitefinity.Security.Claims;
using Telerik.Sitefinity.Security.Claims.SWT;
using Telerik.Sitefinity.Security.Configuration;

namespace SitefinityWebApp.Services
{
    public class WsAuthService
    {
        public static string GenerateEncodedSecret()
        {
            byte[] buffer = new byte[9];

            using (RandomNumberGenerator rng = RNGCryptoServiceProvider.Create())
            {
                rng.GetBytes(buffer);
            }

            var secret = Convert.ToBase64String(buffer).Substring(0, 10).Replace('/', '0').Replace('+', '1');
            return new WsEncoder().Encode(Encoding.ASCII.GetBytes(secret));
        }

        public Uri ProcessRequest(string realm, string redirect_uri, bool deflate, string wrap_name, string sf_persistent)
        {
            var issuer = "http://localhost";
            var idx = issuer.IndexOf("?");
            if (idx != -1)
            {
                issuer = issuer.Substring(0, idx);
            }

            var claims = new List<Claim>() {
                new Claim(ClaimTypes.Name, wrap_name)
            };

            var token = this.CreateToken(claims, issuer, realm);
            NameValueCollection queryString;
            if (!String.IsNullOrEmpty(redirect_uri))
            {
                string path;
                idx = redirect_uri.IndexOf('?');
                if (idx != -1)
                {
                    path = redirect_uri.Substring(0, idx);
                    queryString = HttpUtility.ParseQueryString(redirect_uri.Substring(idx + 1));
                }
                else
                {
                    path = redirect_uri;
                    queryString = new NameValueCollection();
                }
                this.WrapSWT(queryString, token, deflate);
                path = String.Concat(path, ToQueryString(queryString));
                var uri = new Uri(new Uri(realm), path);

                return uri;
            }

            queryString = new NameValueCollection();
            this.WrapSWT(queryString, token, deflate);

            HttpContext.Current.Response.Clear();
            HttpContext.Current.Response.StatusCode = 200;
            HttpContext.Current.Response.ContentType = "application/x-www-form-urlencoded";
            HttpContext.Current.Response.Write(ToQueryString(queryString, false));

            return null;
        }

        private SimpleWebToken CreateToken(List<Claim> claims, string issuerName, string appliesTo)
        {
            var manager = ConfigManager.GetManager();
            var config = manager.GetSection<SecurityConfig>();
            var sKey = config.SecurityTokenIssuers.Values.Where(i => i.Realm == issuerName).SingleOrDefault().Key;
            var key = this.HexToByte(sKey);
            var sb = new StringBuilder();

            foreach (var c in claims)
            {
                sb.AppendFormat("{0}={1}&", HttpUtility.UrlEncode(c.Type), HttpUtility.UrlEncode(c.Value));
            }

            var loginDateClaim = claims.FirstOrDefault(x => x.Type == SitefinityClaimTypes.LastLoginDate);
            DateTime issueDate = DateTime.UtcNow;

            if (loginDateClaim != null)
            {
                if (!DateTime.TryParseExact(loginDateClaim.Value, "u", null, DateTimeStyles.None, out issueDate))
                {
                    issueDate = DateTime.UtcNow;
                }
            }

            sb.AppendFormat("TokenId={0}&", HttpUtility.UrlEncode(Guid.NewGuid().ToString()))
                .AppendFormat("Issuer={0}&", HttpUtility.UrlEncode(issuerName))
                .AppendFormat("Audience={0}&", HttpUtility.UrlEncode(appliesTo))
                .AppendFormat("ExpiresOn={0:0}", (issueDate - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds + 3600);

            var unsignedToken = sb.ToString();

            var hmac = new HMACSHA256(key);
            var sig = hmac.ComputeHash(Encoding.ASCII.GetBytes(unsignedToken));

            string signedToken = String.Format("{0}&HMACSHA256={1}", unsignedToken, HttpUtility.UrlEncode(Convert.ToBase64String(sig)));

            return new SimpleWebToken(signedToken);
        }

        private void WrapSWT(NameValueCollection collection, SimpleWebToken token, bool deflate)
        {
            var rawToken = token.RawToken;
            if (deflate)
            {
                var zipped = this.ZipStr(rawToken);
                rawToken = Convert.ToBase64String(zipped);
                collection["wrap_deflated"] = "true";
            }
            collection["wrap_access_token"] = HttpUtility.UrlEncode(rawToken);
            var seconds = Convert.ToInt32((token.ValidTo - token.ValidFrom).TotalSeconds);
            collection["wrap_access_token_expires_in"] = seconds.ToString();
        }

        private byte[] ZipStr(String str)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (DeflateStream gzip = new DeflateStream(output, CompressionMode.Compress))
                {
                    using (StreamWriter writer = new StreamWriter(gzip, System.Text.Encoding.UTF8))
                    {
                        writer.Write(str);
                    }
                }

                return output.ToArray();
            }
        }

        private byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
            {
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return returnBytes;
        }

        public static string ToQueryString(NameValueCollection collection, bool startWithQuestionMark = true)
        {
            if (collection == null || !collection.HasKeys())
            {
                return String.Empty;
            }

            var sb = new StringBuilder();
            if (startWithQuestionMark)
            {
                sb.Append("?");
            }

            var j = 0;
            var keys = collection.Keys;
            foreach (string key in keys)
            {
                var i = 0;
                var values = collection.GetValues(key);
                foreach (var value in values)
                {
                    sb.Append(key)
                        .Append("=")
                        .Append(value);

                    if (++i < values.Length)
                    {
                        sb.Append("&");
                    }
                }
                if (++j < keys.Count)
                {
                    sb.Append("&");
                }
            }
            return sb.ToString();
        }
    }
}