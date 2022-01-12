using System;
using System.Web.Security;
using Telerik.Microsoft.Practices.Unity;
using Telerik.Sitefinity.Abstractions;
using Telerik.Sitefinity.Authentication;

namespace AutehnticationSamples
{
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            AuthenticationModule.Initialized += this.AuthenticationModule_Initialized;

        }

        private void AuthenticationModule_Initialized(object sender, EventArgs e)
        {
            ObjectFactory.Container.RegisterType<AuthenticationProvidersInitializer, AuthenticationProvidersInitializerExtender>(new ContainerControlledLifetimeManager());
        }
    }
}