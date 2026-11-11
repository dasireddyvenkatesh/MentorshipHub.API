namespace MentorshipHub.API.Constants.Messages;

public static class AdminMessages
{
    public const string SelfDisable = "You cannot disable your own administrator account.";
    public const string UserNotFound = "The requested user could not be found.";
    public const string LastActiveSuperAdminCannotDisable = "The last active Super Admin cannot be disabled.";
    public const string AccountEnabled = "The account has been enabled. The user can sign in again.";
    public const string AccountDisabled = "The account has been disabled and its active sessions have been revoked.";
    public const string SearchTooLong = "Search text cannot exceed 100 characters.";
    public const string RoleCodeTooLong = "Role code cannot exceed 50 characters.";
    public const string InvalidRegistrationDateRange = "The registration start date must be before or equal to the end date.";
    public const string AdministratorIdentityInvalid = "The administrator identity is invalid.";
}
