namespace MentorshipHub.API.Application.DTO.Auth
{
    /// <summary>
    /// Registration-only OTP request. Password and confirmation are collected
    /// after the mailbox owner proves control of the email address.
    /// </summary>
    public sealed class VerifyRegisterEmailOtpRequest : VerifyEmailOtpRequest
    {
        public string? Password { get; set; }
        public string? ConfirmPassword { get; set; }
    }
}