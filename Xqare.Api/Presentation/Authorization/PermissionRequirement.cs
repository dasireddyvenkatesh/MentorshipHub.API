using Microsoft.AspNetCore.Authorization;

namespace MentorshipHub.API.Presentation.Authorization
{
    public sealed class PermissionRequirement : IAuthorizationRequirement
    {
        public PermissionRequirement(string permissionCode)
        {
            PermissionCode = permissionCode;
        }

        public string PermissionCode { get; }
    }
}
