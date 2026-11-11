using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace MentorshipHub.API.Presentation.Swagger;

/// <summary>
/// Documents the API's global fallback authorization policy in OpenAPI.
/// Actions marked with [AllowAnonymous] remain documented as public.
/// </summary>
public sealed class AuthorizationOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var endpointMetadata = context.ApiDescription.ActionDescriptor.EndpointMetadata;

        if (endpointMetadata?.OfType<IAllowAnonymous>().Any() == true)
            return;

        operation.Security ??= [];
        operation.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference("Bearer", context.Document)] = []
        });

        operation.Responses ??= new OpenApiResponses();
        operation.Responses.TryAdd("401", new OpenApiResponse
        {
            Description = "Unauthorized - a valid access token is required."
        });
        operation.Responses.TryAdd("403", new OpenApiResponse
        {
            Description = "Forbidden - the authenticated user lacks the required permission."
        });
    }
}
