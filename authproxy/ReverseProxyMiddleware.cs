using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace authproxy
{

    // started code from: https://auth0.com/blog/building-a-reverse-proxy-in-dot-net-core/

    public class ReverseProxyMiddleware
    {

        public ReverseProxyMiddleware(
            RequestDelegate next,
            ILogger<ReverseProxyMiddleware> logger,
            IHttpClientFactory httpClientFactory
        )
        {
            Next = next;
            this.Logger = logger;
            this.HttpClient = httpClientFactory.CreateClient("authproxy");
        }

        private RequestDelegate Next { get; }
        private ILogger<ReverseProxyMiddleware> Logger { get; }
        private HttpClient HttpClient { get; }

        public async Task Invoke(HttpContext context)
        {

            // determine URL to redirect request to
            string url = $"http://{Program.ToHost}:{Program.ToPort}{context.Request.Path}{context.Request.QueryString}";
            Logger.LogTrace($"redirecting to \"{url}\"...");
            var targetUri = new Uri(url);

            // create request message
            var targetRequestMessage = CreateTargetMessage(context, targetUri);

            // get response
            using (var responseMessage = await HttpClient.SendAsync(targetRequestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted))
            {
                context.Response.StatusCode = (int)responseMessage.StatusCode;
                CopyFromTargetResponseHeaders(context, responseMessage);
                await responseMessage.Content.CopyToAsync(context.Response.Body);
            }

        }

        private HttpRequestMessage CreateTargetMessage(HttpContext context, Uri targetUri)
        {

            // create the message
            var requestMessage = new HttpRequestMessage();

            // copy from original
            CopyFromOriginalRequestContentAndHeaders(context, requestMessage);

            // add URI, host, and method
            requestMessage.RequestUri = targetUri;
            requestMessage.Headers.Host = targetUri.Host;
            requestMessage.Method = GetMethod(context.Request.Method);

            return requestMessage;
        }

        private void CopyFromOriginalRequestContentAndHeaders(HttpContext context, HttpRequestMessage requestMessage)
        {

            // if a method that has body content, copy it
            var requestMethod = context.Request.Method;
            if (!HttpMethods.IsGet(requestMethod) &&
              !HttpMethods.IsHead(requestMethod) &&
              !HttpMethods.IsDelete(requestMethod) &&
              !HttpMethods.IsTrace(requestMethod))
            {
                var streamContent = new StreamContent(context.Request.Body);
                requestMessage.Content = streamContent;
            }

            // copy headers
            foreach (var header in context.Request.Headers)
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }

        }

        private void CopyFromTargetResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
        {

            // copy headers
            foreach (var header in responseMessage.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
            foreach (var header in responseMessage.Content.Headers)
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }

            // remove transfer-encoding because the entire message is buffered
            context.Response.Headers.Remove("transfer-encoding");

        }

        private static HttpMethod GetMethod(string method)
        {
            if (HttpMethods.IsDelete(method)) return HttpMethod.Delete;
            if (HttpMethods.IsGet(method)) return HttpMethod.Get;
            if (HttpMethods.IsHead(method)) return HttpMethod.Head;
            if (HttpMethods.IsOptions(method)) return HttpMethod.Options;
            if (HttpMethods.IsPost(method)) return HttpMethod.Post;
            if (HttpMethods.IsPut(method)) return HttpMethod.Put;
            if (HttpMethods.IsTrace(method)) return HttpMethod.Trace;
            return new HttpMethod(method);
        }

    }
}