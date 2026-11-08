using System.Security.Claims;
using MentorshipHub.API.Application.DTO.Rbac;
using MentorshipHub.API.Application.Interfaces.Rbac;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/admin/rbac")]
    public sealed class RbacController : ControllerBase
    {
        private readonly IRbacService _rbacService;

        public RbacController(IRbacService rbacService)
        {
            _rbacService = rbacService;
        }

        [HttpGet("roles")]
        [Authorize(Policy = "Permission:RBAC_ROLES_VIEW")]
        public async Task<ActionResult<IReadOnlyList<RoleResponse>>> GetRoles()
            => Ok(await _rbacService.GetRolesAsync());

        [HttpPost("roles")]
        [Authorize(Policy = "Permission:RBAC_ROLES_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> CreateRole([FromBody] CreateRoleRequest request)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            var result = await _rbacService.CreateRoleAsync(actorId, request.Name, request.Code, request.PermissionCodes ?? []);
            return MapResult(result);
        }

        [HttpPut("roles/{roleId:guid}")]
        [Authorize(Policy = "Permission:RBAC_ROLES_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> UpdateRole(
            Guid roleId, [FromBody] UpdateRoleRequest request)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            return MapResult(await _rbacService.UpdateRoleAsync(actorId, roleId, request.Name));
        }

        [HttpDelete("roles/{roleId:guid}")]
        [Authorize(Policy = "Permission:RBAC_ROLES_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> DeleteRole(Guid roleId)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            return MapResult(await _rbacService.DeleteRoleAsync(actorId, roleId));
        }

        [HttpGet("permissions")]
        [Authorize(Policy = "Permission:RBAC_PERMISSIONS_VIEW")]
        public async Task<ActionResult<IReadOnlyList<PermissionResponse>>> GetPermissions()
            => Ok(await _rbacService.GetPermissionsAsync());

        [HttpGet("roles/{roleId:guid}/permissions")]
        [Authorize(Policy = "Permission:RBAC_PERMISSIONS_VIEW")]
        public async Task<ActionResult<RolePermissionsResponse>> GetRolePermissions(Guid roleId)
        {
            var result = await _rbacService.GetRolePermissionsAsync(roleId);
            return result is null ? NotFound() : Ok(result);
        }

        [HttpPut("roles/{roleId:guid}/permissions")]
        [Authorize(Policy = "Permission:RBAC_PERMISSIONS_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> SetRolePermissions(
            Guid roleId, [FromBody] SetRolePermissionsRequest request)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            return MapResult(await _rbacService.SetRolePermissionsAsync(
                actorId, roleId, request.PermissionCodes ?? []));
        }

        [HttpPost("assignments")]
        [Authorize(Policy = "Permission:RBAC_ASSIGNMENTS_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> AssignRole([FromBody] RoleAssignmentRequest request)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            return MapResult(await _rbacService.AssignRoleAsync(actorId, request.UserId, request.RoleId));
        }

        [HttpDelete("assignments")]
        [Authorize(Policy = "Permission:RBAC_ASSIGNMENTS_MANAGE")]
        public async Task<ActionResult<RbacOperationResponse>> RemoveRole([FromBody] RoleAssignmentRequest request)
        {
            if (!TryGetActor(out var actorId))
                return Unauthorized();

            return MapResult(await _rbacService.RemoveRoleAsync(actorId, request.UserId, request.RoleId));
        }

        private bool TryGetActor(out Guid actorId)
            => Guid.TryParse(User.FindFirst("uid")?.Value, out actorId);

        private ActionResult<RbacOperationResponse> MapResult(RbacOperationResponse result)
        {
            if (result.IsSuccess)
                return Ok(result);

            return result.ErrorCode switch
            {
                "NOT_FOUND" => NotFound(result),
                "SUPERADMIN_REQUIRED" => StatusCode(StatusCodes.Status403Forbidden, result),
                "ROLE_EXISTS" or "ALREADY_ASSIGNED" or "ROLE_IN_USE" or "SUPERADMIN_PROTECTED" or
                    "SYSTEM_ROLE_PROTECTED" or "RESERVED_ROLE" => Conflict(result),
                _ => BadRequest(result)
            };
        }
    }
}
