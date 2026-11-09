namespace MentorshipHub.API.Constants.Messages;

public static class SessionMessages
{
    public const string RefreshTokenMissing = "Refresh token missing";
    public const string LoginExpired = "Login expired. Please sign in again.";
    public const string MaximumAgeReached = "Maximum session age reached. Please sign in again.";
    public const string AccountInactive = "Account is inactive. Please sign in again.";
    public const string RefreshTokenUpdated = "Refresh Token Updated";
    public const string MfaChallengeExpired = "The MFA challenge has expired. Please sign in again.";
    public const string ActiveSessionsRetrieved = "Active sessions retrieved.";
    public const string SessionNotFoundOrRevoked = "The session was not found or is already revoked.";
    public const string CurrentSessionRevoked = "This session has been revoked.";
    public const string SelectedSessionRevoked = "The selected session has been revoked.";
    public const string NoOtherActiveSessions = "There are no other active sessions.";
    public const string OtherSessionsSignedOut = "{0} other session(s) have been signed out.";
    public const string SignInExchangeExpired = "The sign-in exchange has expired. Please sign in again.";
    public const string RefreshTokenMissingSignIn = "Refresh token missing. Please sign in again.";
}
