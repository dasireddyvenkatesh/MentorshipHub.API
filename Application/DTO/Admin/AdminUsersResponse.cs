namespace MentorshipHub.API.Application.DTO.Admin
{
    public sealed class AdminUsersResponse
    {
        public bool IsSuccess { get; set; } = true;
        public string Message { get; set; } = "Users retrieved.";
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int TotalCount { get; set; }
        public int TotalPages { get; set; }
        public List<AdminUserListItemResponse> Items { get; set; } = new();
    }
}
