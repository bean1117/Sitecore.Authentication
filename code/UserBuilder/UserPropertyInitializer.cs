using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Collections;
using Sitecore.Owin.Authentication.Services;
using Sitecore.Security.Accounts;

namespace Foundation.Auth.UserBuilder
{
    public class UserPropertyInitializer : PropertyInitializer
    {
   
        public UserPropertyInitializer()
        {

        }

        protected override void MapCore(User user, ClaimCollection claimCollection)
        {
            Assert.ArgumentNotNull((object)user, nameof(user));
            Assert.ArgumentNotNull((object)claimCollection, nameof(claimCollection));
            foreach (ClaimToPropertyMapper map in this.Maps)
                map.Map(user, claimCollection);
            user.Profile.Save();
            
        }

    }
}