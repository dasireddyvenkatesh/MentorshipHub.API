using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.ExceptionHandling;

public sealed class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException &&
            httpContext.RequestAborted.IsCancellationRequested)
            return false;

        if (httpContext.Response.HasStarted)
        {
            logger.LogError(exception,
                "Unhandled exception after response started. TraceId: {TraceId}",
                httpContext.TraceIdentifier);
            return false;
        }

        logger.LogError(exception,
            "Unhandled exception for {Method} {Path}. TraceId: {TraceId}",
            httpContext.Request.Method,
            httpContext.Request.Path,
            httpContext.TraceIdentifier);

        httpContext.Response.Clear();
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;

        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "An unexpected error occurred.",
            Type = "about:blank",
            Instance = httpContext.Request.Path
        };
        problem.Extensions["isSuccess"] = false;
        problem.Extensions["message"] = "An unexpected error occurred. Please try again later.";
        problem.Extensions["traceId"] = httpContext.TraceIdentifier;

        await httpContext.Response.WriteAsJsonAsync(
            problem,
            contentType: "application/problem+json",
            cancellationToken: cancellationToken);

        return true;
    }
}
