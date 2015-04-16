using System.Collections.Generic;
using Thinktecture.IdentityServer.Core.Models;

namespace EmbeddedMvc.IdentityServer
{
    public static class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new[]
            {

                new Client 
                {
                    Enabled = true,
                    ClientName = "MVC Client",
                    ClientId = "anothermvc",
                    ClientSecrets = new List<ClientSecret>{new ClientSecret("secret".Sha256())},
                    Flow = Flows.Hybrid,

                    RedirectUris = new List<string>
                    {
                        "https://localhost:44319/",
                        "http://localhost:53141/",
                        "http://localhost:61962/"
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        "https://localhost:44319/",
                        "http://localhost:53141/",
                        "http://localhost:61962/"
                    },
                    AccessTokenType = AccessTokenType.Reference,
                    IdentityTokenLifetime = 360,
                    AccessTokenLifetime = 360,
                },
                new Client 
                {
                    Enabled = true,
                    ClientName = "MVC Client",
                    ClientId = "mvc",
                    ClientSecrets = new List<ClientSecret>{new ClientSecret("secret".Sha256())},
                    Flow = Flows.Hybrid,

                    RedirectUris = new List<string>
                    {
                        "https://localhost:44319/",
                        "http://localhost:53141/",
                        "http://localhost:61962/"
                    },
                    PostLogoutRedirectUris = new List<string>
                    {
                        "https://localhost:44319/",
                        "http://localhost:53141/",
                        "http://localhost:61962/"
                    },
                    AccessTokenType = AccessTokenType.Reference,
                    IdentityTokenLifetime = 360,
                    AccessTokenLifetime = 360,
                },
                new Client
                {
                    Enabled = true,
                    ClientName = "MVC Client (service communication)",
                    
                    ClientId = "mvc_service",
                    ClientSecrets = new List<ClientSecret>
                    {
                        new ClientSecret("secret".Sha256())
                    },
                    
                    Flow = Flows.ClientCredentials
                }
            };
        }
    }
}