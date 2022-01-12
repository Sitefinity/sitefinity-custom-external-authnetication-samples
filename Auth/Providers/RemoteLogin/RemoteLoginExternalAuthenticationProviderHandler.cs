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