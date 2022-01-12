# 14.0 Custom external authentication provider samples
This is the recommended approach when integrating external identity proviers with custom logic.
| :exclamation: THE SAMPLE HERE IS VALID ONLY IF YOU ARE USING THE *DEFAULT* AUTHENTICATION PROTOCOL.   |
|-------------------------------------------------------------------------------------------------------|

Sitefinity ships out of box (OOB) with several external authentication providers (EAP) for several popular Identity Providers (IP or sometimes called STS) like Google, Facebook, Microsoft. It also has one configurable generic EIP for authenticating with systems that follow the widely adopted OpenID Connect (OIDC) authentication protocol. Customizing the OIDC provider is described in this article: [Implement custom external identity providers](https://www.progress.com/documentation/sitefinity-cms/for-developers-implement-custom-external-identity-providers)

![image2021-9-14_13-3-35](https://user-images.githubusercontent.com/56825414/140044202-9263d431-9c17-4771-a8f3-06868b628765.png)

If you cannot use any of the OOB external authentication providers, you can implement a fully custom one by following the samples in this repo. Please note that for the purpose of the demo the samples here are not for production use as there are additional security implementations omitted for brievity.

The job of the EAP is to authenticate the user and then pass a claims based identity to Sitefinity with a few required claims. The repo contains two samples - one where the login page is on a remote server (Remote Login) and one where the login page is in Sitefinity and credentials provided by the user are sent to a remote server for verification (Local Login).
## Sample 1 - Remote Login
1. Create the configuration class - it is used to contain custom settings that you might want to configure via advanced settings view:
 ```
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
```
2. Create the authentication handler class - this is where all the custom logic resides, the class should derive from `AuthenticationHandler<RemoteLoginExternalAuthenticationProviderOptions>` :
```
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using SitefinityWebApp.AuthProvider;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Telerik.Sitefinity.Security.Claims;

namespace AutehnticationSamples
{
    public class RemoteLoginExternalAuthenticationProviderHandler : AuthenticationHandler<RemoteLoginExternalAuthenticationProviderOptions>
    {
        public AuthPropertiesSerializer propertiesSerializer = new AuthPropertiesSerializer();
        
        // handle signin requests - redirect the user browser to the external identity provider for authentication
        protected override Task ApplyResponseChallengeAsync()
        {
            // challenges change the status code to 401
            if (Response.StatusCode != 401)
            {
                return Task.CompletedTask;
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)
            {
                return Task.CompletedTask;
            }

            var redirectUri = challenge.Properties.RedirectUri;

            // you should also cryptographically protect the state or do not send the entire obejct
            // but store it in db and send only an identifier associated with it
            var state = this.propertiesSerializer.Serialize(challenge.Properties);
            redirectUri = redirectUri + "?state=" + HttpUtility.UrlEncode(state);

            // the url of the identity provider where authentication should take place
            var ipUri = Options.IdentityProviderAddress;
            ipUri = ipUri + "/authorize?callbackUri=" + HttpUtility.UrlEncode(redirectUri);

            Response.Redirect(ipUri);
            return Task.CompletedTask;
        }

        public override async Task<bool> InvokeAsync()
        {
            AuthenticationTicket ticket = TryProcessResponseFromIP();
            if (ticket != null)
            {
                if (ticket.Identity != null)
                {
                    Request.Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
                }
            }

            return false;
        }

        // try to handle the redirect back from the external identity provider with the authentication token and return null if failed or
        // the generated identity if successful
        protected AuthenticationTicket TryProcessResponseFromIP()
        {
            // extract user information from redirect request back from IP 
            // token should be cryptographically protected
            // also avoid sending the token in the request query, instead a POST request with the token in the body should be implemented for increased security
            // or something similar to authorization code flow of OAuth2.0 protocol could be implemented
            var token = HttpUtility.UrlDecode(Context.Request.Query.Get("token"));
            var state = HttpUtility.UrlDecodeToBytes(Context.Request.Query.Get("state"));

            // return null if unsuccessful
            if (token == null || state == null)
            {
                return null;
            }

            // otherwise generate an identity with calims required by Sitefinity
            // sub identifier is required it must be unique for each user on the external system
            // email is required if turned on in the advanced settings
            var tokenParts = token.Split(':');
            var externalId = tokenParts[0];
            var email = tokenParts[1];
            ClaimsIdentity identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
            identity.AddClaim(new Claim("sub", externalId));
            identity.AddClaim(new Claim(SitefinityClaimTypes.ExternalUserEmail, email));

            // optionally you can also add profile picture claim - SitefinityClaimTypes.ExternalUserPictureUrl
            // to map any other information from the remote server about the user to the automatically created user profile use
            // the following KB: https://knowledgebase.progress.com/articles/Article/Authentication-What-types-of-claims-can-be-mapped-to-profile-fields-when-using-a-custom-external-identity-provider

            // state must be further cryptographically protected
            var props = this.propertiesSerializer.Deserialize(state);
            var ticket = new AuthenticationTicket(identity, props);

            return ticket;
        }

        // handle signout requests
        protected override Task ApplyResponseGrantAsync()
        {
            AuthenticationResponseRevoke signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (signout != null)
            {
                // send a request to the IP to signout the user
                Response.Redirect(Options.IdentityProviderAddress + "/signoutCurrent" + "?redirectUri=" + HttpUtility.UrlEncode(signout.Properties.RedirectUri));
            }

            return Task.CompletedTask;
        }

        // the auth middleware is concerned with delegating the authentication to a remote system
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return Task.FromResult<AuthenticationTicket>(null);
        }
    }
}
```
The handler depends on a serializer class for the auth properties, here`s the implementation:
```
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.IO;

namespace SitefinityWebApp.AuthProvider
{
    public class AuthPropertiesSerializer
    {
        private const int FormatVersion = 1;

        public byte[] Serialize(AuthenticationProperties model)
        {
            using (var memory = new MemoryStream())
            {
                using (var writer = new BinaryWriter(memory))
                {
                    Write(writer, model);
                    writer.Flush();
                    return memory.ToArray();
                }
            }
        }

        public AuthenticationProperties Deserialize(byte[] data)
        {
            using (var memory = new MemoryStream(data))
            {
                using (var reader = new BinaryReader(memory))
                {
                    return Read(reader);
                }
            }
        }

        public static void Write(BinaryWriter writer, AuthenticationProperties properties)
        {
            if (writer == null)
            {
                throw new ArgumentNullException("writer");
            }
            if (properties == null)
            {
                throw new ArgumentNullException("properties");
            }

            writer.Write(FormatVersion);
            writer.Write(properties.Dictionary.Count);
            foreach (var kv in properties.Dictionary)
            {
                writer.Write(kv.Key);
                writer.Write(kv.Value);
            }
        }

        public static AuthenticationProperties Read(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException("reader");
            }

            if (reader.ReadInt32() != FormatVersion)
            {
                return null;
            }
            int count = reader.ReadInt32();
            var extra = new Dictionary<string, string>(count);
            for (int index = 0; index != count; ++index)
            {
                string key = reader.ReadString();
                string value = reader.ReadString();
                extra.Add(key, value);
            }
            return new AuthenticationProperties(extra);
        }
    }
}
```
3. Create the custom authentication middleware class:
```

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
```
4. Register the custom authentication middleware with Sitefinity:
```
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

            return providers;
        }
    }
}
```
and in the `Global.asax` file:
```
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
```
5. Finally start Sitefinity and go to advanced settings and create a new authentication provider element:

![image2021-9-16_15-20-46](https://user-images.githubusercontent.com/56825414/140046287-f11e2edf-d45d-4cbb-a4eb-67b2249e7e02.png)

6. Use the same name that you used when registering the custom authentication provider in the `AuthenticationProvidersInitializerExtender`, in this sample *CustomIP*

![image2021-9-16_15-23-50](https://user-images.githubusercontent.com/56825414/140046428-bdb6b5ae-9e6d-448b-a914-a59662979dbc.png)

7. Next add the properties that you want to be able to configure via advanced settings and that you have added to the `emoteLoginExternalAuthenticationProviderOptions` class.
   In this demo we only want to be able to configure the address of the external Identity Provider.
   
![image2021-9-16_15-25-42](https://user-images.githubusercontent.com/56825414/140046627-99c086a2-1adc-4c2a-b58b-430ed62dc77e.png)

## Sample 2 - Local Login

If you want to host the login page locally and only send the credentials to the IP for verification use this sample for the authentication handler class. Here for the purpose of the demo we host the login page in the handler itself.
```
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using SitefinityWebApp.AuthProvider;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Telerik.Sitefinity.Security.Claims;
using Telerik.Sitefinity.Web;

namespace AutehnticationSamples
{
    public class LocalLoginExternalAuthenticationProviderHandler : AuthenticationHandler<LocalLoginExternalAuthenticationProviderOptions>
    {
        private const string LocalCustomLoginPagePath = "custom-login";
        public AuthPropertiesSerializer propertiesSerializer = new AuthPropertiesSerializer();

        // this middleware is concerned only with proper redirection to a custom login page that contains the authentication logic
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return null;
        }

        // handle signin requests - redirect the user browser to the external identity provider for authentication
        protected override Task ApplyResponseChallengeAsync()
        {
            // challenges change the status code to 401
            if (Response.StatusCode != 401)
            {
                return Task.CompletedTask;
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)
            {
                return Task.CompletedTask;
            }

            // redirect to a login page, you can redirect to any sitefinity page with custom widget
            // for simplicity we will handle the page request in the same auth middleware
            Response.Redirect(
                UrlPath.ResolveAbsoluteUrl(
                    "~/" + LocalCustomLoginPagePath + "?redirectUrl=" + HttpUtility.UrlEncode(challenge.Properties.RedirectUri)) + "&singInAs=" + HttpUtility.UrlEncode(Options.SignInAsAuthenticationType));

            return Task.CompletedTask;
        }

        public override async Task<bool> InvokeAsync()
        {
            // for brevity we handle the login page processing in the middleware but that logic could be extracted in any codebehind of a widget or page outside of this middleware
            if (Request.Uri.GetLeftPart(UriPartial.Path).ToLower() == UrlPath.ResolveAbsoluteUrl("~/" + LocalCustomLoginPagePath).ToLower())
            {
                await HandleCustomLoginPageRequest();
                return true; // stop further processing
            }

            return false;
        }

        private async Task HandleCustomLoginPageRequest()
        {
            if (Request.Method == "GET")
            {
                // render login page
                await Response.WriteAsync($@"<!DOCTYPE html>
<html>
<body>
<h2>Custom Sitefinity Login</h2>

<form action='{Request.Uri}' method='POST'>
  <label for='user'>User:</label><br>
  <input type='text' id='user' name='user'><br>
  <label for='pass'>Pass:</label><br>
  <input type='password' id='pass' name='pass'><br><br>
  <input type='submit' value='Submit'>
</form> 
</body>
</html>
");
            }
            else if (Request.Method == "POST")
            {
                // handle login page post with credentials

                // extract the credentials from the post request and send them via secure backchannel communication in the backend for verification on a trusted remote server
                // this is similar to OAuth2.0 ResourceOwner flow where you have two trusted apps communicating directly without redirecting the user browser
                var form = await Request.ReadFormAsync();
                var user = form.Get("user");
                var pass = form.Get("pass");

                // send the credentials to a remote server for verification using secure backchannel
                // for this to be secure the remote server must be trusted and this call should always be made via encrypted transport layer protocol like TLS from the backend, never from browser script
                using (var client = new HttpClient())
                {
                    client.SetBasicAuthentication(user, pass);
                    var request = new HttpRequestMessage(HttpMethod.Get, UrlPath.ResolveAbsoluteUrl("~/customIP/remoteVerification"));
                    var response = await client.SendAsync(request);
                    if (response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Sitefinity requires unique identifier for the external identity
                        // in this sample the authorization server returns the use unique identifier after successful verification
                        // it is used to match the remote account to the locally created Sitefinity user
                        // if the user does not exist Sitefinity will create one automatically and bind it to the external one via the id 
                        // if turned on in the provider advanced settings configuration Sitefinity will also require email and match accounts based on it as well
                        var externalId = await response.Content.ReadAsStringAsync();
                        var email = user;
                        ClaimsIdentity identity = new ClaimsIdentity(Request.Query.Get("singInAs"));
                        identity.AddClaim(new Claim("sub", externalId));
                        identity.AddClaim(new Claim(SitefinityClaimTypes.ExternalUserEmail, email));

                        // optionally you can also add profile picture claim - SitefinityClaimTypes.ExternalUserPictureUrl
                        // to map any other information from the remote server about the user to the automatically created user profile use
                        // the following KB: https://knowledgebase.progress.com/articles/Article/Authentication-What-types-of-claims-can-be-mapped-to-profile-fields-when-using-a-custom-external-identity-provider

                        // state must be further cryptographically protected
                        var props = new AuthenticationProperties() { RedirectUri = Request.Query.Get("redirectUrl") };
                        props.Dictionary.Add("externalProviderName", "LocalLoginCustomIP");
                        Request.Context.Authentication.SignIn(props, identity);
                    }
                }
            }
        }
    }
}
```
## Sample 3 - Dummy identitiy provider for testing purposes
You can use this sample to test the above custom auth provders:

| :exclamation: Keep in mind that nothing here is production ready and needs further security checks and encryption.   |
|----------------------------------------------------------------------------------------------------------------------|

```
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace AutehnticationSamples.DummyIdentityProvider
{
    /// <summary>
    /// Identity providers are separate web apps, but for the purpose of the demo we are hosting it inside Sitefinity
    /// </summary>
    public class DummyIdentityProviderMiddleware : OwinMiddleware
    {
        public DummyIdentityProviderMiddleware(OwinMiddleware next) : base(next)
        {
        }

        public override Task Invoke(IOwinContext context)
        {
            if (context.Request.Path.Value.ToLower().StartsWith("/customip/authorize"))
            {
                // process user authentication and generate response to send back to Sitefinity
                var dummyAuthToken = HttpUtility.UrlEncode("id1:user1@test.test");
                context.Response.Redirect(context.Request.Query.Get("callbackUri") + "&token=" + dummyAuthToken);
                return Task.CompletedTask;
            }
            else if (context.Request.Path.Value.ToLower().StartsWith("/customip/signout"))
            {
                // signout the user from the Identity Provider and redirect back to Sitefinity
                return Task.CompletedTask;
            }
            else if (context.Request.Path.Value.ToLower().StartsWith("/customip/remoteverification"))
            {
                // verify the credentials sent by Sitefinity backend and return user unique id if successful
                // this endpoint is used by the LocalLogin external auth provider
                // for the purpose of the sample the endpoint will return the hash of the user email as unique identifier
                var authHeader = context.Request.Headers.Get("Authorization");
                var encoding = Encoding.GetEncoding("iso-8859-1");
                var credentials = encoding.GetString(Convert.FromBase64String(authHeader.Split(' ')[1]));

                int separator = credentials.IndexOf(':');
                string userEmail = credentials.Substring(0, separator);
                context.Response.WriteAsync(new HMACMD5().ComputeHash(encoding.GetBytes(userEmail)));
                return Task.CompletedTask;
            }
            else
            {
                return Next.Invoke(context);
            }

        }
    }
}
```
Next, create a startup class to register t he dummy identity provider
```
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
```
Finally, register the startup class in the web.config:

![image2021-9-16_15-38-48](https://user-images.githubusercontent.com/56825414/140047449-3db66e8e-d528-4e8b-bb50-7351353715a0.png)
