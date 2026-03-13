using MentorshipHub.API.Application.Interfaces.Email;
using System.Text;

namespace MentorshipHub.API.Application.Services.Email
{
    public class EmailTemplateService : IEmailTemplateService
    {
        public (string subject, string body) BuildRegistrationOtp(string firstName, string otpCode)
        {
            string subject = "Your XQARE Email Verification Code";

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html>");
            sb.Append("<body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");

            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");

            sb.Append("<h2 style='color:#333;'>Verify your email</h2>");

            sb.Append($"<p>Hi {firstName},</p>");

            sb.Append("<p>");
            sb.Append("To complete your registration on <strong>XQARE</strong>, please use the verification code below.");
            sb.Append("</p>");

            sb.Append("<div style='font-size:30px;font-weight:bold;letter-spacing:5px;text-align:center;margin:30px 0;'>");
            sb.Append(otpCode);
            sb.Append("</div>");

            sb.Append("<p>This code will expire in <strong>10 minutes</strong>.</p>");

            sb.Append("<p style='color:#777;'>For security reasons, please do not share this code with anyone.</p>");

            sb.Append("<p style='color:#999;'>If you did not request this code, you can safely ignore this email.</p>");

            sb.Append("<br>");

            sb.Append("<p>Best regards,<br><strong>Team XQARE</strong></p>");

            sb.Append("</div>");
            sb.Append("</body>");
            sb.Append("</html>");

            return (subject, sb.ToString());
        }

        public (string subject, string body) BuildResendOtp(string firstName, string otpCode)
        {
            string subject = "Resend verification code for XQARE";

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html>");
            sb.Append("<body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");

            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");

            sb.Append("<h2 style='color:#333;'>Your new verification code</h2>");

            sb.Append($"<p>Hi {firstName},</p>");

            sb.Append("<p>You requested a new verification code for your <strong>XQARE</strong> account.</p>");

            sb.Append("<p>Please use the code below to verify your email:</p>");

            sb.Append("<div style='font-size:32px;font-weight:bold;letter-spacing:6px;text-align:center;margin:30px 0;'>");
            sb.Append(otpCode);
            sb.Append("</div>");

            sb.Append("<p>This code will expire in <strong>10 minutes</strong>.</p>");

            sb.Append("<p style='color:#777;'>For security reasons, please do not share this code with anyone.</p>");

            sb.Append("<p style='color:#999;'>If you did not request this code, you can safely ignore this email.</p>");

            sb.Append("<br>");

            sb.Append("<p>Best regards,<br><strong>Team XQARE</strong></p>");

            sb.Append("</div>");
            sb.Append("</body>");
            sb.Append("</html>");

            return (subject, sb.ToString());
        }

        public (string subject, string body) BuildMfaOtp(string firstName, string otpCode)
        {
            string subject = "Your XQARE Multi-Factor Authentication Code";

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html>");
            sb.Append("<body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");

            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");

            sb.Append("<h2 style='color:#333;'>Multi-Factor Authentication</h2>");

            sb.Append($"<p>Hi {firstName},</p>");

            sb.Append("<p>");
            sb.Append("We detected a sign-in attempt to your <strong>XQARE</strong> account. ");
            sb.Append("Please use the verification code below to complete your login.");
            sb.Append("</p>");

            sb.Append("<div style='font-size:30px;font-weight:bold;letter-spacing:5px;text-align:center;margin:30px 0;'>");
            sb.Append(otpCode);
            sb.Append("</div>");

            sb.Append("<p>This code will expire in <strong>10 minutes</strong>.</p>");

            sb.Append("<p style='color:#777;'>For your security, never share this code with anyone.</p>");

            sb.Append("<p style='color:#999;'>If you did not attempt to sign in, please secure your account immediately or contact support.</p>");

            sb.Append("<br>");

            sb.Append("<p>Best regards,<br><strong>Team XQARE</strong></p>");

            sb.Append("</div>");
            sb.Append("</body>");
            sb.Append("</html>");

            return (subject, sb.ToString());
        }
    }
}