namespace MentorshipHub.API.Application.DTO.Common
{
    public class ResponseDTO
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; } = default!;
    }
}
