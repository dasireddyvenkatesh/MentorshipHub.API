using MentorshipHub.API.Application.DTO.Email;
using MentorshipHub.API.Application.Interfaces.Email;
using System.Text;
using System.Text.Json;

namespace MentorshipHub.API.Application.Services.Email
{
    public class EmailService : IEmailService
    {
        public async Task<bool> SendEmail(string to, string subject, string body)
        {
            var apiKey = "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";

            EmailMessageModel emailMessage = new EmailMessageModel
            {
                Sender = new EmailMessageModel.SenderInfo
                {
                    Email = "noreplyinternalxqare@gmail.com",
                    Name = "Xqare"
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
