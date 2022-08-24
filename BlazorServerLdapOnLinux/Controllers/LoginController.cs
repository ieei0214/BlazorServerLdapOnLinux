using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Novell.Directory.Ldap;

namespace BlzLogin.Controllers
{
    public class LoginController : Controller
    {
        public static bool SimpleLdapAuth(string username, string password, out LdapEntry? resultEntity)
        {
            var Host = "ldap.forumsys.com";
            var BindDN = "cn=read-only-admin,dc=example,dc=com";
            var BindPassword = "password";
            var BaseDC = "dc=example,dc=com";

            resultEntity = null;

            try
            {
                using (var connection = new LdapConnection())
                {
                    connection.Connect(Host, LdapConnection.DefaultPort);
                    connection.Bind(BindDN, BindPassword);

                    var searchFilter = $"(uid={username})";
                    var entities = connection.Search(BaseDC, LdapConnection.ScopeSub, searchFilter, null, false);

                    string userDn = null;
                    while (entities.HasMore())
                    {
                        var entity = entities.Next();
                        var account = entity.GetAttribute("uid");
                        if (account != null && account.StringValue == username)
                        {
                            userDn = entity.Dn;
                            resultEntity = entity;
                            break;
                        }
                    }
                    if (string.IsNullOrWhiteSpace(userDn)) return false;

                    connection.Bind(userDn, password);
                    return connection.Bound;
                }
            }
            catch (LdapException e)
            {
                throw e;
            }
        }
        [HttpPost("/account/login")]
        public async Task<IActionResult> Login(UserCredentials credentials)
        {
            var User = new { username = credentials.Username, password = credentials.Password };

            var result = SimpleLdapAuth(User.username, User.password,out var resultEntity);

            if (result == true)
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, User.username),
                    new Claim(ClaimTypes.Role, $"{resultEntity.GetAttribute("gidNumber").StringValue}")
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);
                return LocalRedirect("/");
            }

            return LocalRedirect("/login/Invalid credentials");
        }

        [HttpGet("/account/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return LocalRedirect("/");
        }
    }

    public class UserCredentials
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}

