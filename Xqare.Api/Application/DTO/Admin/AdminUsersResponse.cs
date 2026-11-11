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
        public List<AdminUserRoleFilterOption> AvailableRoles { get; set; } = new();
        public List<AdminUserListItemResponse> Items { get; set; } = new();
    }

    public sealed class AdminUserRoleFilterOption
    {
        public string Name { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}