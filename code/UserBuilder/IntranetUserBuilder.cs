using Microsoft.AspNet.Identity;
using Sitecore.DependencyInjection;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;
using Sitecore.SecurityModel.Cryptography;
using System;
using System.Linq;

namespace Foundation.Auth.UserBuilder
{
    public class IntranetUserBuilder : Sitecore.Owin.Authentication.Services.DefaultExternalUserBuilder
    {
        public IntranetUserBuilder(ApplicationUserFactory applicationUserFactory, IHashEncryption hashEncryption) :base(applicationUserFactory, hashEncryption)
        {
        }

        protected override string CreateUniqueUserName(UserManager<ApplicationUser> userManager, Microsoft.AspNet.Identity.Owin.ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull((object)userManager, nameof(userManager));
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            IdentityProvider identityProvider = this.FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);
            if (identityProvider == null)
                throw new InvalidOperationException("Unable to retrieve identity provider for given identity");
            string domain = identityProvider.Domain;
            string email = externalLoginInfo.Email;

            var preferred_username = externalLoginInfo.ExternalIdentity.Claims.Where(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
           .Select(c => c.Value).SingleOrDefault();
            if (!string.IsNullOrEmpty(preferred_username))
            {
                return $"{domain}\\{preferred_username}";
            }
            // return email and domain
            return $"{domain}\\{email}";

        }

    }
}