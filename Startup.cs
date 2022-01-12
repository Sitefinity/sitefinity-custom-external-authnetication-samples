using AutehnticationSamples.DummyIdentityProvider;
using Owin;
using Telerik.Sitefinity.Owin;

namespace AutehnticationSamples
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Register default Sitefinity middlewares in the pipeline
            app.UseSitefinityMiddleware();

            app.Use(typeof(DummyIdentityProviderMiddleware));
        }
    }
}