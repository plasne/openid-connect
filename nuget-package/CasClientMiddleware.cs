using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;

namespace CasAuth
{

    public class CasClientAuthMiddleware
    {
        // used just for ILogger
    }

    public static class UseCasClientAuthMiddlewareExtensions
    {

        private class HttpException : Exception
        {

            public HttpException(int code, string msg) : base(msg)
            {
                this.StatusCode = code;
            }

            public int StatusCode { get; set; }
        }

        public static IApplicationBuilder UseCasClientAuth(this IApplicationBuilder builder)
        {

            // define additional endpoints
            builder.UseEndpoints(endpoints =>
            {

                // define options preflight
                endpoints.MapMethods("/cas/{**all}", new string[] { "OPTIONS" }, context =>
                {
                    context.Response.StatusCode = 204;
                    return context.Response.CompleteAsync();
                }).RequireCors("cas-client");

                // define the configuration endpoint
                endpoints.MapGet("/cas/config/{name}", async context =>
                {
                    try
                    {
                        string name = (string)context.Request.RouteValues["name"];

                        // validate the name is alpha numeric only
                        if (!name.All(char.IsLetterOrDigit)) throw new HttpException(400, $"config name of '{name}' is not alphanumeric.");

                        // look for env that would allow this config
                        string compact = System.Environment.GetEnvironmentVariable($"PRESENT_CONFIG_{name.ToUpper()}");
                        if (string.IsNullOrEmpty(compact)) throw new HttpException(404, $"config name of '{name}' is not found (1).");
                        var filters = compact.Split(',').Select(id => id.Trim()).ToArray();
                        if (filters.Count() < 1) throw new HttpException(404, $"config name of '{name}' is not found (2).");

                        // return the config
                        var httpClientFactory = context.RequestServices.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");
                        var config = await CasConfig.Load(httpClient, filters);
                        string json = JsonSerializer.Serialize(config);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        await context.Response.WriteAsync(json);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/config/{name}");
                        await context.Response.WriteAsync("internal server error");
                    }
                }).RequireCors("cas-client");

                // define the "me" endpoint
                endpoints.MapGet("/cas/me", context =>
                {
                    try
                    {

                        // filter the claims
                        var filtered = context.User.Claims.FilterToSignificant();

                        // project to a dictionary
                        var projected = new Dictionary<string, object>();
                        foreach (var claim in filtered)
                        {
                            string key = claim.ShortType();
                            if (projected.ContainsKey(key))
                            {
                                var obj = projected[key];
                                if (obj is string)
                                {
                                    projected[key] = new List<string>() { (string)obj, claim.Value };
                                }
                                else
                                {
                                    ((List<string>)projected[key]).Add(claim.Value);
                                }
                            }
                            else
                            {
                                projected.Add(key, claim.Value);
                            }
                        }

                        // return the serialized user info
                        string json = JsonSerializer.Serialize(projected);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        return context.Response.WriteAsync(json);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        return context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/me");
                        return context.Response.WriteAsync("internal server error");
                    }
                }).RequireCors("cas-client").RequireAuthorization(new AuthorizeAttribute("cas"));

                // define the clear-client-cache endpoint
                endpoints.MapPost("/cas/clear-client-cache", context =>
                {
                    try
                    {

                        // find the validator and use it to clear cache
                        var validator = context.RequestServices.GetService<CasTokenValidator>();
                        validator.ConfigManager.RequestRefresh();

                        // respond with success
                        return context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        return context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/clear-client-cache");
                        return context.Response.WriteAsync("internal server error");
                    }
                }).RequireCors("cas-client").RequireAuthorization(new AuthorizeAttribute("cas") { Roles = CasEnv.RoleForAdmin });

                // define the validation thumbprints endpoint
                endpoints.MapGet("/cas/validation-thumbprints", async context =>
                {
                    try
                    {

                        // get the configuration
                        var list = new List<string>();
                        var validator = context.RequestServices.GetService<CasTokenValidator>();
                        var config = await validator.ConfigManager.GetConfigurationAsync();
                        foreach (var key in config.SigningKeys)
                        {
                            if (!list.Contains(key.KeyId)) list.Add(key.KeyId);
                        }

                        // serialize and respond
                        string json = JsonSerializer.Serialize(config);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        await context.Response.WriteAsync(json);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/validation-thumbprints");
                        await context.Response.WriteAsync("internal server error");
                    }
                }).RequireCors("cas-client").RequireAuthorization(new AuthorizeAttribute("cas") { Roles = CasEnv.RoleForAdmin });

            });
            return builder;

        }

    }

}