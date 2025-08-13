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
            var bindUrls = AppViewLiteConfiguration.GetStringList(AppViewLiteParameter.APPVIEWLITE_BIND_URLS) ?? new[] { "https://localhost:61749", "http://localhost:61750" };
            builder.WebHost.UseUrls(bindUrls);

            // Logging & services
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(new LogWrapper.Provider());
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

            // Scoped session & context
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
                var signalrConnectionId = request?.Headers["X-AppViewLiteSignalrId"].FirstOrDefault();
                var urgent = request?.Method != "CONNECT" && request?.Headers["X-AppViewLiteUrgent"].FirstOrDefault() != "0";

                return RequestContext.CreateForRequest(session, string.IsNullOrEmpty(signalrConnectionId) ? null : signalrConnectionId, urgent: urgent, requestUrl: httpContext?.Request.GetEncodedPathAndQuery());
            });

            builder.Services.AddSignalR();

            // HTTPS redirection
            var bindHttps = bindUrls.FirstOrDefault(x => x.StartsWith("https://", StringComparison.Ordinal));
            if (bindHttps != null)
            {
                var port = bindHttps.Split(':').ElementAtOrDefault(2)?.Replace("/", null);
                if (port != null)
                {
                    builder.Services.Configure<HttpsRedirectionOptions>(options =>
                    {
                        options.HttpsPort = int.Parse(port);
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
                    LoggableBase.Log("Ctx was not passed for " + httpContext.Request.GetEncodedPathAndQuery());
            };
#endif
            app.Lifetime.ApplicationStopping.Register(apis.NotifyShutdownRequested);

            // Middleware
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }
            app.UseForwardedHeaders();
            if (bindHttps != null) app.UseHttpsRedirection();
            app.UseStatusCodePagesWithReExecute("/ErrorHttpStatus", "?code={0}");
            app.UseAntiforgery();
            app.UseRouting();
            app.UseCors();
            app.UseAntiforgery();
            app.MapRazorComponents<App>();
            app.MapHub<AppViewLiteHub>("/api/live-updates");
            app.MapControllers();
            app.MapStaticAssets();

            // Firehose & labelers
            if (listenToFirehose && !relationships.IsReadOnly)
            {
                await Task.Delay(1000);
                app.Logger.LogInformation("Indexing the firehose to {0}... (press CTRL+C to stop indexing)", relationships.BaseDirectory);
                var firehoses = AppViewLiteConfiguration.GetStringList(AppViewLiteParameter.APPVIEWLITE_FIREHOSES) ?? new[] { "jet:jetstream1.us-west.bsky.network" };

                foreach (var firehose in firehoses)
                {
                    if (firehose == "-") continue;
                    var isJetStream = firehose.StartsWith("jet:");
                    var firehoseUrl = isJetStream ? "https://" + firehose.AsSpan(4) : "https://" + firehose;

                    var indexer = new Indexer(apis)
                    {
                        FirehoseUrl = new Uri(firehoseUrl),
                        VerifyValidForCurrentRelay = did =>
                        {
                            if (apis.DidDocOverrides.GetValue().CustomDidDocs.ContainsKey(did))
                                throw new Exception($"Ignoring firehose record for {did} because a DID doc override was specified.");
                        }
                    };

                    if (isJetStream) indexer.StartListeningToJetstreamFirehose().FireAndForget();
                    else indexer.StartListeningToAtProtoFirehoseRepos(retryPolicy: null).FireAndForget();
                }
            }

            // PLC directory listener
            if ((AppViewLiteConfiguration.GetBool(AppViewLiteParameter.APPVIEWLITE_LISTEN_TO_PLC_DIRECTORY) ?? true) && !relationships.IsReadOnly)
            {
                Task.Run(async () =>
                {
                    var indexer = new Indexer(apis);
                    var bundle = AppViewLiteConfiguration.GetString(AppViewLiteParameter.APPVIEWLITE_PLC_DIRECTORY_BUNDLE);
                    if (bundle != null) await indexer.InitializePlcDirectoryFromBundleAsync(bundle);

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

            // SignalR
            AppViewLiteHubContext = app.Services.GetRequiredService<IHubContext<AppViewLiteHub>>();
            RequestContext.SendSignalrImpl = (signalrSessionId, method, args) => AppViewLiteHubContext.Clients.Client(signalrSessionId).SendCoreAsync(method, args);

            LoggableBase.Log("AppViewLite is now serving requests on ========> " + string.Join(", ", bindUrls));
            app.Run();
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
                    var token = authorization.Substring(7).Trim();
                    return token + "=" + new JwtSecurityTokenHandler().ReadJwtToken(token).Subject;
                }
                return null;
            }
            return httpContext.Request.Cookies.TryGetValue("appviewliteSessionId", out var id) && !string.IsNullOrEmpty(id) ? id : null;
        }
    }
}
