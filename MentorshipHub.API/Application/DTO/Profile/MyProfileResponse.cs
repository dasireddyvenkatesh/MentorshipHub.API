namespace MentorshipHub.API.Application.DTO.Profile
{
    public sealed class MyProfileResponse
    {
        public bool IsSuccess { get; set; } = true;
        public string Message { get; set; } = "Profile retrieved successfully.";
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string Bio { get; set; } = string.Empty;
        public bool IsEmailConfirmed { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public List<string> Roles { get; set; } = new();
    }
}
