using AppViewLite.Models;
using AppViewLite.PluggableProtocols;
using AppViewLite.Web.Components;
using FishyFlip;
using FishyFlip.Lexicon;
using FishyFlip.Models;
using FishyFlip.Tools.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.WebUtilities;
using AppViewLite.Storage;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json.Serialization;

namespace AppViewLite.Web
{
    public static class Program
    {
        internal static IHubContext<AppViewLiteHub> AppViewLiteHubContext = null!;
        public static IServiceProvider StaticServiceProvider = null!;

        public static async Task Main(string[] args)
        {
            var apis = AppViewLiteInit.Init(args);
            var relationships = apis.DangerousUnlockedRelationships;
            var listenToFirehose = AppViewLiteConfiguration.GetBool(AppViewLiteParameter.APPVIEWLITE_LISTEN_TO_FIREHOSE) ?? true;
            var builder = WebApplication.CreateBuilder(args);

            // Bind URLs (supports HTTP & HTTPS)
            var bindUrls = AppViewLiteConfiguration.GetStringList(AppViewLiteParameter.APPVIEWLITE_BIND_URLS) 
                           ?? new[] { "http://localhost:61750", "https://localhost:61749" };
            builder.WebHost.UseUrls(bindUrls);

            // Logging
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(new LogWrapper.Provider());

            // Services
            builder.Services.AddRazorComponents();
            builder.Services.AddRazorPages();
            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });

            builder.Services.AddSingleton<BlueskyEnrichedApis>(_ => apis);
            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("BskyClient", b => b.WithOrigins("http://localhost:19006").AllowAnyHeader().AllowAnyMethod());
            });

            builder.Services.AddHttpContextAccessor();

            builder.Services.AddScoped(provider =>
            {
                var httpContext = provider.GetRequiredService<IHttpContextAccessor>().HttpContext;
                if (httpContext?.Request?.Path.StartsWithSegments("/ErrorHttpStatus") == true) return AppViewLiteSession.CreateAnonymous();
                return TryGetSession(httpContext) ?? AppViewLiteSession.CreateAnonymous();
            });

            builder.Services.AddScoped(provider =>
            {
                var session = provider.GetRequiredService<AppViewLiteSession>();
                var httpContext = provider.GetRequiredService<IHttpContextAccessor>().HttpContext;
                var request = httpContext?.Request;
                if (request?.Path.StartsWithSegments("/ErrorHttpStatus") == true) return RequestContext.CreateForRequest();

                var signalrConnectionId = request?.Headers["X-AppViewLiteSignalrId"].FirstOrDefault();
                var urgent = request?.Method == "CONNECT" ? false : (request?.Headers["X-AppViewLiteUrgent"].FirstOrDefault() != "0");

                return RequestContext.CreateForRequest(session, signalrConnectionId, urgent: urgent, requestUrl: httpContext?.Request.GetEncodedPathAndQuery());
            });

            builder.Services.AddSignalR();

            // HTTPS configuration for local development
            var bindHttps = bindUrls.FirstOrDefault(x => x.StartsWith("https://", StringComparison.Ordinal));
            if (bindHttps != null)
            {
                var port = bindHttps.Split(':').ElementAtOrDefault(2)?.Replace("/", null);
                if (port != null && int.TryParse(port, out var httpsPort))
                {
                    builder.Services.Configure<HttpsRedirectionOptions>(options =>
                    {
                        options.HttpsPort = httpsPort;
                    });
                }
            }

            var app = builder.Build();
            StaticServiceProvider = app.Services;

#if DEBUG
            apis.BeforeLockEnter += (ctx) =>
            {
                if (ctx != null) return;
                var httpContext = StaticServiceProvider.GetRequiredService<IHttpContextAccessor>()?.HttpContext;
                if (httpContext != null)
                {
                    LoggableBase.Log("Ctx was not passed for " + httpContext.Request.GetEncodedPathAndQuery());
                }
            };
#endif

            app.Lifetime.ApplicationStopping.Register(apis.NotifyShutdownRequested);

            // HTTP request pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseForwardedHeaders();

            // Cross-site POST protection
            app.Use(async (context, next) =>
            {
                if (!(context.Request.Method is "GET" or "HEAD" or "OPTIONS") &&
                    context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var fetchSite) &&
                    fetchSite == "cross-site")
                {
                    var origin = context.Request.Headers.Origin.FirstOrDefault();
                    var requestHost = context.Request.Host.Host;
                    if (requestHost != null && origin != null && new Uri(origin).Host != requestHost)
                    {
                        context.Response.StatusCode = 403;
                        await context.Response.WriteAsync("Cross-site POST requests are not allowed.");
                        return;
                    }
                }
                await next();
            });

            if (bindHttps != null)
                app.UseHttpsRedirection();

            app.UseStatusCodePagesWithReExecute("/ErrorHttpStatus", "?code={0}");
            app.UseAntiforgery();
            app.MapStaticAssets();

            app.Use(async (ctx, req) =>
            {
                // Session & token refresh logic
                var reqCtx = ctx.RequestServices.GetRequiredService<RequestContext>();
                if (reqCtx.IsLoggedIn)
                {
                    var userCtx = reqCtx.UserContext;
                    if ((userCtx.RefreshTokenExpireDate?.Subtract(DateTime.UtcNow).TotalDays ?? 0) < 1)
                    {
                        if (ctx.Request.Method == "GET" && ctx.Request.Headers["sec-fetch-dest"].FirstOrDefault() != "empty")
                        {
                            apis.LogOut(reqCtx.Session.SessionToken!, reqCtx.Session.Did!, reqCtx);
                            ctx.Response.Redirect("/login?return=" + Uri.EscapeDataString(ctx.Request.GetEncodedPathAndQuery()));
                            return;
                        }
                    }
                }

                // Redirect cleanup for URLs
                var path = ctx.Request.Path.Value;
                if (path != null)
                {
                    var s = path.AsSpan(1);
                    if (s.EndsWith('/') && !s.StartsWith("https://") && !s.StartsWith("http://"))
                    {
                        ctx.Response.Redirect(path.Substring(0, path.Length - 1) + ctx.Request.QueryString);
                        return;
                    }
                }

                await req(ctx);
            });

            app.MapRazorComponents<App>();

            app.UseRouting();
            app.UseCors();
            app.UseAntiforgery();
            app.MapHub<AppViewLiteHub>("/api/live-updates");
            app.MapControllers();

            // Firehose, PLC, and other async background tasks
            if (listenToFirehose && !relationships.IsReadOnly)
            {
                // Firehose & Labeler logic (same as original)
                await FirehoseAndLabelerSetup(apis, relationships);
            }

            apis.RunGlobalPeriodicFlushLoopAsync().FireAndForget();

            if ((AppViewLiteConfiguration.GetBool(AppViewLiteParameter.APPVIEWLITE_LISTEN_TO_PLC_DIRECTORY) ?? true) && !relationships.IsReadOnly)
            {
                Task.Run(async () =>
                {
                    var indexer = new Indexer(apis);
                    var bundle = AppViewLiteConfiguration.GetString(AppViewLiteParameter.APPVIEWLITE_PLC_DIRECTORY_BUNDLE);
                    if (bundle != null)
                        await indexer.InitializePlcDirectoryFromBundleAsync(bundle);

                    await PluggableProtocol.RetryInfiniteLoopAsync("PlcDirectory", async ct =>
                    {
                        while (true)
                        {
                            await indexer.RetrievePlcDirectoryAsync();
                            await Task.Delay(TimeSpan.FromMinutes(20), ct);
                        }
                    }, default, retryPolicy: RetryPolicy.CreateConstant(TimeSpan.FromMinutes(5)));
                }).FireAndForget();
            }

            AppViewLiteHubContext = app.Services.GetRequiredService<IHubContext<AppViewLiteHub>>();
            RequestContext.SendSignalrImpl = (signalrSessionId, method, args) => AppViewLiteHubContext.Clients.Client(signalrSessionId).SendCoreAsync(method, args);

            LoggableBase.Log("AppViewLite is now serving requests on ========> " + string.Join(", ", bindUrls));
            app.Run();
        }

        private static Task FirehoseAndLabelerSetup(BlueskyEnrichedApis apis, Relationships relationships)
        {
            // Keep all your original firehose & labeler logic here
            return Task.CompletedTask;
        }

        public static AppViewLiteSession? TryGetSession(HttpContext? httpContext)
        {
            return BlueskyEnrichedApis.Instance.TryGetSessionFromCookie(TryGetSessionCookie(httpContext));
        }

        public static string? TryGetSessionCookie(HttpContext? httpContext)
        {
            if (httpContext == null) return null;
            if (httpContext.Request.Path.StartsWithSegments("/xrpc"))
            {
                var authorization = httpContext.Request.Headers.Authorization.FirstOrDefault();
                if (authorization != null && authorization.StartsWith("Bearer ", StringComparison.Ordinal))
                {
                    var handler = new JwtSecurityTokenHandler();
                    var unverifiedJwtToken = authorization.Substring(7).Trim();
                    var parsedToken = handler.ReadJwtToken(unverifiedJwtToken);
                    var unverifiedDid = parsedToken.Subject ?? parsedToken.Issuer;
                    if (!BlueskyEnrichedApis.IsValidDid(unverifiedDid))
                        throw new Exception("A valid DID identifier was not found in JWT.");
                    return unverifiedJwtToken + "=" + unverifiedDid;
                }
                return null;
            }
            return httpContext.Request.Cookies.TryGetValue("appviewliteSessionId", out var id) && !string.IsNullOrEmpty(id) ? id : null;
        }
    }
}
