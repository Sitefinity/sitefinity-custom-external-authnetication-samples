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