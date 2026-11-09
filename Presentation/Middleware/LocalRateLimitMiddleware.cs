using Microsoft.AspNetCore.RateLimiting;

namespace MentorshipHub.API.Presentation.Middleware;

/// <summary>
/// Process-local fixed-window counters. A single lock keeps partition creation,
/// window rollover, and request counting atomic without external storage.
/// </summary>
public sealed class LocalRateLimitStore
{
    private const int MaxPartitions = 25_000;
    private readonly object _gate = new();
    private readonly Dictionary<(string Policy, string ClientIp), WindowState> _windows = new();
    private readonly TimeProvider _timeProvider = TimeProvider.System;
    private long _operations;

    public RateLimitDecision TryAcquire(
        string policy,
        string clientIp,
        int permitLimit,
        TimeSpan window)
    {
        var now = _timeProvider.GetTimestamp();

        lock (_gate)
        {
            _operations++;
            if ((_operations & 127) == 0)
                RemoveExpiredPartitions(now);

            var key = (policy, clientIp);
            if (!_windows.TryGetValue(key, out var state))
            {
                if (_windows.Count >= MaxPartitions)
                {
                    RemoveExpiredPartitions(now);
                    if (_windows.Count >= MaxPartitions)
                        return RateLimitDecision.Rejected(1);
                }

                state = new WindowState(now, now, 0, window);
                _windows.Add(key, state);
            }

            var elapsed = _timeProvider.GetElapsedTime(state.WindowStartedAt, now);
            if (elapsed >= window)
            {
                state.WindowStartedAt = now;
                state.RequestCount = 0;
                elapsed = TimeSpan.Zero;
            }

            state.LastAccessAt = now;

            if (state.RequestCount < permitLimit)
            {
                state.RequestCount++;
                return RateLimitDecision.Allowed();
            }

            var remaining = window - elapsed;
            var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
            return RateLimitDecision.Rejected(retryAfterSeconds);
        }
    }

    private void RemoveExpiredPartitions(long now)
    {
        List<(string Policy, string ClientIp)>? expired = null;

        foreach (var entry in _windows)
        {
            var idleFor = _timeProvider.GetElapsedTime(entry.Value.LastAccessAt, now);
            if (idleFor <= TimeSpan.FromTicks(entry.Value.Window.Ticks * 2))
                continue;

            expired ??= new List<(string Policy, string ClientIp)>();
            expired.Add(entry.Key);
        }

        if (expired is null)
            return;

        foreach (var key in expired)
            _windows.Remove(key);
    }

    private sealed class WindowState(
        long windowStartedAt,
        long lastAccessAt,
        int requestCount,
        TimeSpan window)
    {
        public long WindowStartedAt { get; set; } = windowStartedAt;
        public long LastAccessAt { get; set; } = lastAccessAt;
        public int RequestCount { get; set; } = requestCount;
        public TimeSpan Window { get; } = window;
    }
}

public readonly record struct RateLimitDecision(bool IsAllowed, int RetryAfterSeconds)
{
    public static RateLimitDecision Allowed() => new(true, 0);
    public static RateLimitDecision Rejected(int retryAfterSeconds) => new(false, retryAfterSeconds);
}

/// <summary>
/// Applies the existing endpoint policy metadata using process-local fixed windows.
/// Must run after forwarded headers and endpoint authorization.
/// </summary>
public sealed class LocalRateLimitMiddleware(
    RequestDelegate next,
    ILogger<LocalRateLimitMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context, LocalRateLimitStore store)
    {
        var policyName = context.GetEndpoint()?
            .Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName;

        if (string.IsNullOrWhiteSpace(policyName) ||
            !TryGetPolicy(policyName, out var permitLimit, out var window))
        {
            await next(context);
            return;
        }

        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var decision = store.TryAcquire(policyName, clientIp, permitLimit, window);

        if (decision.IsAllowed)
        {
            await next(context);
            return;
        }

        var response = context.Response;
        response.StatusCode = StatusCodes.Status429TooManyRequests;
        response.ContentType = "application/json";
        response.Headers["Retry-After"] = decision.RetryAfterSeconds.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        response.Headers["X-RateLimit-Policy"] = policyName;

        var instanceId = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")
            ?? Environment.MachineName;

        // Deliberately exclude client IPs and all authentication material from logs.
        logger.LogWarning(
            "Rate limit rejected. Policy={Policy}; RetryAfterSeconds={RetryAfterSeconds}; Instance={Instance}; TimestampUtc={TimestampUtc}",
            policyName,
            decision.RetryAfterSeconds,
            instanceId,
            DateTimeOffset.UtcNow);

        await response.WriteAsJsonAsync(
            new
            {
                isSuccess = false,
                code = "rate_limit_exceeded",
                policy = policyName,
                retryAfterSeconds = decision.RetryAfterSeconds,
                message = "Too many requests. Please wait before trying again."
            },
            cancellationToken: context.RequestAborted);
    }

    private static bool TryGetPolicy(
        string policyName,
        out int permitLimit,
        out TimeSpan window)
    {
        (permitLimit, window) = policyName switch
        {
            "auth-login-ip" => (30, TimeSpan.FromMinutes(5)),
            "auth-otp-ip" => (20, TimeSpan.FromMinutes(5)),
            "auth-recovery-ip" => (10, TimeSpan.FromMinutes(10)),
            "auth-security-ip" => (30, TimeSpan.FromMinutes(5)),
            _ => (0, TimeSpan.Zero)
        };

        return permitLimit > 0;
    }
}
