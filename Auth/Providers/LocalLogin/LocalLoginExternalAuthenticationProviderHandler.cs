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