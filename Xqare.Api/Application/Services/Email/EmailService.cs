using MentorshipHub.API.Application.DTO.Email;
using MentorshipHub.API.Application.Interfaces.Email;
using System.Text;
using System.Text.Json;

namespace MentorshipHub.API.Application.Services.Email
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<bool> SendEmail(string to, string subject, string body)
        {
            var apiKey = _configuration["Email:ApiKey"];

            EmailMessageModel emailMessage = new EmailMessageModel
            {
                Sender = new EmailMessageModel.SenderInfo
                {
                    Email = "noreply@xqare.in",
                    Name = "No Reply"
                },
                To = new List<EmailMessageModel.RecipientInfo>
                {
                    new EmailMessageModel.RecipientInfo
                    {
                        Email = to,
                        Name = "XqareUser"
                    }
                },
                Subject = subject,
                HtmlContent = body
            };

            var emailMessagetJson = JsonSerializer.Serialize(emailMessage);

            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("api-key", apiKey);

            var content = new StringContent(emailMessagetJson, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("https://api.brevo.com/v3/smtp/email", content);

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            return false;
        }
    }
}
