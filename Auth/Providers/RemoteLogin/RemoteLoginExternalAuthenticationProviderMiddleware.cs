using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace AutehnticationSamples
{
    public class RemoteLoginExternalAuthenticationProviderMiddleware : AuthenticationMiddleware<RemoteLoginExternalAuthenticationProviderOptions>
    {
        public RemoteLoginExternalAuthenticationProviderMiddleware(OwinMiddleware next, RemoteLoginExternalAuthenticationProviderOptions options) : base(next, options)
        {
        }

        protected override AuthenticationHandler<RemoteLoginExternalAuthenticationProviderOptions> CreateHandler()
        {
            return new RemoteLoginExternalAuthenticationProviderHandler();
        }
    }
}