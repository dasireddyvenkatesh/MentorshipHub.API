using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace MentorshipHub.API.Presentation.Authorization
{
    public sealed class PermissionPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        public const string PolicyPrefix = "Permission:";

        public PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
            : base(options)
        {
        }

        public override Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith(PolicyPrefix, StringComparison.OrdinalIgnoreCase))
            {
                var permissionCode = policyName[PolicyPrefix.Length..].Trim();
                if (string.IsNullOrWhiteSpace(permissionCode))
                    return Task.FromResult<AuthorizationPolicy?>(null);

                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddRequirements(new PermissionRequirement(permissionCode))
                    .Build();

                return Task.FromResult<AuthorizationPolicy?>(policy);
            }

            return base.GetPolicyAsync(policyName);
        }
    }
}
