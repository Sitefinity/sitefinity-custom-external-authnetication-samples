using Owin;
using System;
using System.Collections.Generic;
using Telerik.Sitefinity.Authentication;
using Telerik.Sitefinity.Authentication.Configuration.SecurityTokenService.ExternalProviders;

namespace AutehnticationSamples
{
    public class AuthenticationProvidersInitializerExtender : AuthenticationProvidersInitializer
    {
        public override Dictionary<string, Action<IAppBuilder, string, AuthenticationProviderElement>> GetAdditionalIdentityProviders()
        {
            var providers = base.GetAdditionalIdentityProviders();

            // 'CustomIP' is the name of the external authentication provider as configured in the Advanced settings
            providers.Add("CustomIP", (IAppBuilder app, string signInAsType, AuthenticationProviderElement providerConfig) =>
            {
                var options = new RemoteLoginExternalAuthenticationProviderOptions(providerConfig.Name)
                {
                    AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive,
                    IdentityProviderAddress = providerConfig.GetParameter("identityProviderAddress"),
                    SignInAsAuthenticationType = signInAsType
                };

                app.Use(typeof(RemoteLoginExternalAuthenticationProviderMiddleware), options);
            });

            providers.Add("LocalLoginCustomIP", (IAppBuilder app, string signInAsType, AuthenticationProviderElement providerConfig) =>
            {
                var options = new LocalLoginExternalAuthenticationProviderOptions(providerConfig.Name)
                {
                    AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive,
                    SignInAsAuthenticationType = signInAsType
                };

                app.Use(typeof(LocalLoginExternalAuthenticationProviderMiddleware), options);
            });

            return providers;
        }
    }
}