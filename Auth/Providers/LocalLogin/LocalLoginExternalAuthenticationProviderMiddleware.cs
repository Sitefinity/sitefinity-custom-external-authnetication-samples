using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AutehnticationSamples
{
    public class LocalLoginExternalAuthenticationProviderMiddleware : AuthenticationMiddleware<LocalLoginExternalAuthenticationProviderOptions>
    {
        public LocalLoginExternalAuthenticationProviderMiddleware(OwinMiddleware next, LocalLoginExternalAuthenticationProviderOptions options) : base(next, options)
        {
        }

        protected override AuthenticationHandler<LocalLoginExternalAuthenticationProviderOptions> CreateHandler()
        {
            return new LocalLoginExternalAuthenticationProviderHandler();
        }
    }
}