namespace Xqare.Api.Application.DTO.Auth
{
    public class ConnectedAccountsResponse
    {
        public bool IsSuccess { get; set; }
        public string Email { get; set; } = string.Empty;
        public bool HasPassword { get; set; }
        public List<string> ConnectedProviders { get; set; } = new();
        public string Message { get; set; } = string.Empty;
    }
}