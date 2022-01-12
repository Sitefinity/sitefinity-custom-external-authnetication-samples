using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AutehnticationSamples
{
    public class LocalLoginExternalAuthenticationProviderOptions : AuthenticationOptions
    {
        public LocalLoginExternalAuthenticationProviderOptions(string authenticationType) : base(authenticationType)
        {
        }

        public string SignInAsAuthenticationType { get; set; }
    }
}