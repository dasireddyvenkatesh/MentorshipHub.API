using System.Text.Json.Serialization;

namespace MentorshipHub.API.Application.DTO.Email
{
    public class EmailMessageModel
    {
        [JsonPropertyName("sender")]
        public SenderInfo Sender { get; set; }

        [JsonPropertyName("to")]
        public List<RecipientInfo> To { get; set; }

        [JsonPropertyName("subject")]
        public string Subject { get; set; }

        [JsonPropertyName("htmlContent")]
        public string HtmlContent { get; set; }

        public class SenderInfo
        {
            [JsonPropertyName("email")]
            public string Email { get; set; }

            [JsonPropertyName("name")]
            public string Name { get; set; }
        }

        public class RecipientInfo
        {
            [JsonPropertyName("email")]
            public string Email { get; set; }

            [JsonPropertyName("name")]
            public string Name { get; set; }
        }
    }
}
