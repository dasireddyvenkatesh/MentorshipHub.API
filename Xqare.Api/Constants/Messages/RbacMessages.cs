namespace Xqare.Api.Constants.Messages;

public static class RbacMessages
{
    public const string InvalidRole = "Provide a valid role name and code.";
    public const string ReservedRole = "The SUPERADMIN role code is reserved.";
    public const string RoleExists = "A role with this code already exists.";
    public const string TooManyPermissions = "A role cannot have more than 200 permissions.";
    public const string UnknownPermission = "One or more permission codes are not in the permission catalogue.";
    public const string CreateDelegationRequiresSuperAdmin = "Only an active Super Admin can delegate role-permission or role-assignment management.";
    public const string RoleCreated = "The role and its permissions were created.";
    public const string RoleNameLength = "Role name must contain between 2 and 80 characters.";
    public const string RoleNotFound = "The role could not be found.";
    public const string SystemRoleRenameProtected = "System roles cannot be renamed.";
    public const string NoChangesRequired = "No changes were required.";
    public const string RoleUpdated = "The role was updated.";
    public const string SystemRoleDeleteProtected = "System roles cannot be deleted.";
    public const string RoleInUse = "Remove all users from this role before deleting it.";
    public const string RoleDeleted = "The role was deleted.";
    public const string UserOrRoleNotFound = "The user or role could not be found.";
    public const string DisabledUserAssignment = "A role cannot be assigned to a disabled account.";
    public const string SuperAdminAssignmentProtected = "SUPERADMIN assignments must be managed through the protected recovery process.";
    public const string AssignDelegatedRoleRequiresSuperAdmin = "Only an active Super Admin can assign a role that grants role-permission or role-assignment management.";
    public const string AlreadyAssigned = "The user already has this role.";
    public const string RoleAssigned = "The role was assigned to the user.";
    public const string AssignmentNotFound = "The user-role assignment could not be found.";
    public const string SuperAdminRemovalProtected = "SUPERADMIN assignments cannot be removed through this endpoint.";
    public const string RoleRemoved = "The role was removed from the user.";
    public const string SystemRolePermissionsProtected = "System role permissions are protected.";
    public const string AddDelegatedPermissionRequiresSuperAdmin = "Only an active Super Admin can add role-permission or role-assignment management to a custom role.";
    public const string NoPermissionChangesRequired = "No permission changes were required.";
    public const string PermissionsUpdated = "Role permissions were updated.";
}
