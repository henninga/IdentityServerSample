using EmbeddedMvc.IdentityServer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Thinktecture.IdentityModel.Client;
using Thinktecture.IdentityServer.Core;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Logging;
using System.Linq;
using Thinktecture.IdentityServer.Core.Configuration.Hosting;
using System.Web.Helpers;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityServer.Core.Logging.LogProviders;

[assembly: OwinStartup(typeof(EmbeddedMvc.Startup))]

namespace EmbeddedMvc
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());

            AntiForgeryConfig.UniqueClaimTypeIdentifier = Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Subject;
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.Map("/identity", idsrvApp =>
                {
                    idsrvApp.UseIdentityServer(new IdentityServerOptions
                    {
                        SiteName = "Embedded IdentityServer",
                        SigningCertificate = LoadCertificate(),

                        Factory = InMemoryFactory.Create(
                            users: Users.Get(),
                            clients: Clients.Get(),
                            scopes: Scopes.Get()),

                        AuthenticationOptions = new Thinktecture.IdentityServer.Core.Configuration.AuthenticationOptions
                        {
                            IdentityProviders = ConfigureIdentityProviders
                        },
                        LoggingOptions = new LoggingOptions
                        {
                            EnableHttpLogging = true, EnableWebApiDiagnostics = true, IncludeSensitiveDataInLogs = true, WebApiDiagnosticsIsVerbose = true
                        },
                        
                    });
                });

            app.UseResourceAuthorization(new AuthorizationManager());

            app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "Cookies"
                });


            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
                {
                    Authority = "https://localhost:44319/identity",

                    ClientId = "mvc",
                    ClientSecret = "secret",
                    Scope = "openid email profile roles sampleApi",
                    ResponseType = "code id_token token",
                    RedirectUri = "https://localhost:44319/",

                    SignInAsAuthenticationType = "Cookies",
                    UseTokenLifetime = false,

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        SecurityTokenValidated = async n =>
                            {
                                var nid = new ClaimsIdentity(
                                    n.AuthenticationTicket.Identity.AuthenticationType,
                                    Thinktecture.IdentityServer.Core.Constants.ClaimTypes.GivenName,
                                    Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Role);

                                // get userinfo data
                                var userInfoClient = new UserInfoClient(
                                    new Uri(n.Options.Authority + "/connect/userinfo"),
                                    n.ProtocolMessage.AccessToken);

                                var userInfo = await userInfoClient.GetAsync();
                                userInfo.Claims.ToList().ForEach(ui => nid.AddClaim(new Claim(ui.Item1, ui.Item2)));

                                // keep the id_token for logout
                                nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                                // add access token for sample API
                                nid.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));

                                // keep track of access token expiration
                                nid.AddClaim(new Claim("expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));

                                // add some other app specific claim
                                nid.AddClaim(new Claim("app_specific", "some data"));

                                //n.AuthenticationTicket = new AuthenticationTicket(
                                    //nid,
                                    //n.AuthenticationTicket.Properties);
                            },

                        AuthorizationCodeReceived = async n =>
                        {
                            // filter "protocol" claims
                            var claims = new List<Claim>(from c in n.AuthenticationTicket.Identity.Claims
                                                         where c.Type != "iss" &&
                                                               c.Type != "aud" &&
                                                               c.Type != "nbf" &&
                                                               c.Type != "exp" &&
                                                               c.Type != "iat" &&
                                                               c.Type != "nonce" &&
                                                               c.Type != "c_hash" &&
                                                               c.Type != "at_hash"
                                                         select c);

                            // get userinfo data
                            var userInfoClient = new UserInfoClient(
                                new Uri(Constants.UserInfoEndpoint),
                                n.ProtocolMessage.AccessToken);

                            var userInfo = await userInfoClient.GetAsync();
                            userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Item1, ui.Item2)));

                            // get access and refresh token
                            var tokenClient = new OAuth2Client(
                                new Uri(Constants.TokenEndpoint),
                                "mvc","secret");

                            var response = await tokenClient.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri);

                            claims.Add(new Claim("access_token", response.AccessToken));
                            claims.Add(new Claim("expires_at", DateTime.Now.AddSeconds(response.ExpiresIn).ToLocalTime().ToString()));

                            if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                                claims.Add(new Claim("refresh_token", response.RefreshToken));

                            claims.Add(new Claim("id_token", n.ProtocolMessage.IdToken));

                            n.AuthenticationTicket = new AuthenticationTicket(new ClaimsIdentity(claims.Distinct(new ClaimComparer()), n.AuthenticationTicket.Identity.AuthenticationType), n.AuthenticationTicket.Properties);
                        },

                        RedirectToIdentityProvider = async n =>
                            {
                                if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                                {
                                    var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                                    if (idTokenHint != null)
                                    {
                                        n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                    }
                                }
                            }
                    }
                });
        }

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
                {
                    AuthenticationType = "Google",
                    Caption = "Sign-in with Google",
                    SignInAsAuthenticationType = signInAsType,

                    ClientId = "701386055558-9epl93fgsjfmdn14frqvaq2r9i44qgaa.apps.googleusercontent.com",
                    ClientSecret = "3pyawKDWaXwsPuRDL7LtKm_o"
                });
        }

        X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(
                string.Format(@"{0}\bin\identityServer\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }

        public static class Constants
        {
            public const string BaseAddress = "https://localhost:44319/identity";

            public const string AuthorizeEndpoint = BaseAddress + "/connect/authorize";
            public const string LogoutEndpoint = BaseAddress + "/connect/endsession";
            public const string TokenEndpoint = BaseAddress + "/connect/token";
            public const string UserInfoEndpoint = BaseAddress + "/connect/userinfo";
            public const string IdentityTokenValidationEndpoint = BaseAddress + "/connect/identitytokenvalidation";
            public const string TokenRevocationEndpoint = BaseAddress + "/connect/revocation";
        }
    }

    public class DebugLogProvider : ILogProvider
    {
        public ILog GetLogger(string name)
        {
            return new ColouredConsoleLogProvider.ColouredConsoleLogger("debug");
        }
    }
}