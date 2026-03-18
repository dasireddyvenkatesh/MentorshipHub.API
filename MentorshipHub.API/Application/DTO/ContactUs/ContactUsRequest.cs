namespace MentorshipHub.API.Application.DTO.ContactUs
{
    public class ContactUsRequest
    {
        public string FullName { get; set; } = default!;
        public string Email { get; set; } = default!;
        public string Subject { get; set; } = default!;
        public string Message { get; set; } = default!;
    }
}
