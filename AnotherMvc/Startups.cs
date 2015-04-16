using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web.Helpers;
using AnotherMvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Thinktecture.IdentityModel;
using Thinktecture.IdentityModel.Client;

[assembly: OwinStartup(typeof(Startups))]

namespace AnotherMvc
{
    public class Startups
    {
        public void Configuration(IAppBuilder app)
        {

            AntiForgeryConfig.UniqueClaimTypeIdentifier = Thinktecture.IdentityServer.Core.Constants.ClaimTypes.Subject;
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            

            app.UseCookieAuthentication(new CookieAuthenticationOptions
                {
                    AuthenticationType = "Cookies"
                });


            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
                {
                    Authority = "https://localhost:44319/identity",

                    ClientId = "anothermvc",
                    ClientSecret = "secret",
                    Scope = "openid email profile roles sampleApi",
                    ResponseType = "code id_token token",
                    RedirectUri = "http://localhost:61962/",

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

                            n.AuthenticationTicket = new AuthenticationTicket(
                                nid,
                                n.AuthenticationTicket.Properties);
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
                                "anothermvc", "secret");

                            var response = await tokenClient.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri);

                            claims.Add(new Claim("access_token", response.AccessToken));
                            claims.Add(new Claim("expires_at", DateTime.Now.AddSeconds(response.ExpiresIn).ToLocalTime().ToString()));

                            if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                                claims.Add(new Claim("refresh_token", response.RefreshToken));

                            claims.Add(new Claim("id_token", n.ProtocolMessage.IdToken));

                            n.AuthenticationTicket = new AuthenticationTicket(new ClaimsIdentity(claims.Distinct(new ClaimComparer()), n.AuthenticationTicket.Identity.AuthenticationType), n.AuthenticationTicket.Properties);
                        },

                        //AuthorizationCodeReceived = async n =>
                        //{
                        //    // filter "protocol" claims
                        //    var claims = new List<Claim>(from c in n.AuthenticationTicket.Identity.Claims
                        //                                 where c.Type != "iss" &&
                        //                                       c.Type != "aud" &&
                        //                                       c.Type != "nbf" &&
                        //                                       c.Type != "exp" &&
                        //                                       c.Type != "iat" &&
                        //                                       c.Type != "nonce" &&
                        //                                       c.Type != "c_hash" &&
                        //                                       c.Type != "at_hash"
                        //                                 select c);

                        //    // get userinfo data
                        //    var userInfoClient = new UserInfoClient(
                        //        new Uri(Constants.UserInfoEndpoint),
                        //        n.ProtocolMessage.AccessToken);

                        //    var userInfo = await userInfoClient.GetAsync();
                        //    userInfo.Claims.ToList().ForEach(ui => claims.Add(new Claim(ui.Item1, ui.Item2)));

                        //    // get access and refresh token
                        //    var tokenClient = new OAuth2Client(
                        //        new Uri(Constants.TokenEndpoint),
                        //        "implicitclient",
                        //        "secret");

                        //    var response = await tokenClient.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri);

                        //    claims.Add(new Claim("access_token", response.AccessToken));
                        //    claims.Add(new Claim("expires_at", DateTime.Now.AddSeconds(response.ExpiresIn).ToLocalTime().ToString()));

                        //    if (!string.IsNullOrWhiteSpace(response.RefreshToken))
                        //        claims.Add(new Claim("refresh_token", response.RefreshToken));

                        //    claims.Add(new Claim("id_token", n.ProtocolMessage.IdToken));

                        //    n.AuthenticationTicket = new AuthenticationTicket(new ClaimsIdentity(claims.Distinct(new ClaimComparer()), n.AuthenticationTicket.Identity.AuthenticationType), n.AuthenticationTicket.Properties);
                        //},

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

    
}