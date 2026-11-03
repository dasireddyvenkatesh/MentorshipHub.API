namespace MentorshipHub.API.Application.DTO.Auth
{
    /// <summary>
    /// Registration-only email verification request. Password and confirmation
    /// are mandatory for this flow; login email verification uses VerifyEmailOtpRequest.
    /// </summary>
    public sealed class VerifyRegisterEmailOtpRequest : VerifyEmailOtpRequest
    {
    }
}
