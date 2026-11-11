namespace Xqare.Api.Application.DTO.Auth
{
    public class VerifyMfaChallengeRequest
    {
        public string Code { get; set; } = string.Empty;
        public string Factor { get; set; } = "auto";
        public string? ChallengeToken { get; set; }
    }
}
