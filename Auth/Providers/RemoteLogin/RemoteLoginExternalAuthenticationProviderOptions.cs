using Microsoft.Owin.Security;

namespace AutehnticationSamples
{
    public class RemoteLoginExternalAuthenticationProviderOptions : AuthenticationOptions
    {
        public RemoteLoginExternalAuthenticationProviderOptions(string authenticationType) : base(authenticationType)
        {
        }

        public string IdentityProviderAddress { get; set; }
        public string SignInAsAuthenticationType { get; set; }
    }
}