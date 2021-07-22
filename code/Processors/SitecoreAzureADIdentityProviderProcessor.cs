using Owin;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Globalization;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Sitecore.Abstractions;
using Microsoft.Owin.Infrastructure;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Cryptography.X509Certificates;
using System;
using System.Text;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Foundation.Auth.Processors
{
    public class SitecoreAzureADIdentityProviderProcessor : IdentityProvidersProcessor
    {
        public SitecoreAzureADIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration, ICookieManager cookieManager, BaseSettings settings)
            : base(federatedAuthenticationConfiguration, cookieManager, settings)
        {

        }
        protected override string IdentityProviderName
        {
            get { return "sitecoreazureAD"; }
        }
        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));

            var identityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();

            string aadInstance = Settings.GetSetting("AADInstance");
            string tenant = Settings.GetSetting("Sitecore_Tenant");
            string clientId = Settings.GetSetting("Sitecore_ClientId");
            string postLogoutRedirectURI = Settings.GetSetting("Sitecore_PostLogoutRedirectURI");
            string redirectURI = Settings.GetSetting("Sitecore_RedirectURI");
            string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
            var clientCertificate = CertificateUtility.FindCertificateByThumbprint(Settings.GetSetting("Sitecore_ClientCertificate"), false);

            var openIdConnectOptions = new OpenIdConnectAuthenticationOptions
            {
                Caption = identityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = AuthenticationMode.Passive,
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectURI,
                RedirectUri = redirectURI,
                Scope = "offline_access",
                CookieManager = CookieManager,
                ResponseType = "code",
                RedeemCode = false,

                // Watch for Events
                Notifications = new OpenIdConnectAuthenticationNotifications
                {

                    // When everything is passed
                    SecurityTokenValidated = async notification =>
                    {
                        // Get the Ident object from Ticket
                        var identity = notification.AuthenticationTicket.Identity;


                        // Use Sitecore Claim Transformation Service to generate additional claims like role or admin
                        foreach (var claimTransformationService in identityProvider.Transformations)
                        {
                            claimTransformationService.Transform(identity,
                                new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }

                        //Get Body
                        var requestForm = await notification.Request.ReadFormAsync();

                        //Save Auth Code to Claim for Future Use
                        identity.AddClaim(new System.Security.Claims.Claim("idp", this.IdentityProviderName));

                        // needed for external logout
                        identity.AddClaim(new System.Security.Claims.Claim("id_token", notification.ProtocolMessage.IdToken));

                        // Create new Auth Ticket
                        notification.AuthenticationTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);

                        //Returns blank task
                        return;
                    },
                    AuthorizationCodeReceived = context =>
                    {
                        var scopes = new List<string> { "User.Read" };

                        // POC: Turn in Auth Code for ID_Token
                        var idClient = ConfidentialClientApplicationBuilder.Create(clientId)
                                             .WithRedirectUri(redirectURI)
                                             //.WithClientSecret("4LsP0vaQZ9DtaNH~7ducIv-T.HQ5e.Ar0l")
                                             .WithCertificate(clientCertificate)
                                             .WithAuthority(authority)
                                             .Build();

                        var result = idClient.AcquireTokenByAuthorizationCode(scopes, context.ProtocolMessage.Code).ExecuteAsync().GetAwaiter().GetResult();

                        //Create Token Endpoint Response
                        var tokenEndPointResponse = new OpenIdConnectMessage
                        {
                            IdToken = result.IdToken
                        };

                        //Set Response
                        context.TokenEndpointResponse = tokenEndPointResponse;

                        return Task.FromResult(0);
                    }


                },

            };

            //Turn off Issuer Validation
            openIdConnectOptions.TokenValidationParameters.ValidateIssuer = false;
            args.App.UseOpenIdConnectAuthentication(openIdConnectOptions);

        }

    }

    public static class CertificateUtility
    {
        /// <summary>
        /// Finds the cert having thumbprint supplied from store location supplied
        /// </summary>
        /// <param name="storeName"></param>
        /// <param name="storeLocation"></param>
        /// <param name="thumbprint"></param>
        /// <param name="validationRequired"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 FindCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint, bool validationRequired)
        {
            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var col = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validationRequired);
                if (col == null || col.Count == 0)
                {
                    throw new ArgumentException("certificate was not found in store");
                }

                return col[0];
            }
            finally
            {
#if NET451
                // IDisposable not implemented in NET451
                store.Close();
#else
                // Close is private in DNXCORE, but Dispose calls close internally
                store.Dispose();
#endif
            }
        }

        /// <summary>
        ///Finds the cert having thumbprint supplied defaulting to the personal store of currrent user. 
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="validateCertificate"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 FindCertificateByThumbprint(string thumbprint, bool validateCertificate)
        {
            return FindCertificateByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint, validateCertificate);
        }

        /// <summary>
        /// Exports the cert supplied into a byte arrays and secures it with a randomly generated password. 
        ///</summary>
        /// <param name="cert"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] ExportCertificateWithPrivateKey(X509Certificate2 cert, out string password)
        {
            password = Convert.ToBase64String(Encoding.Unicode.GetBytes(Guid.NewGuid().ToString("N")));
            return cert.Export(X509ContentType.Pkcs12, password);


        }
    }
}

