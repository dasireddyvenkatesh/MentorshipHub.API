using Azure.Core;
using MentorshipHub.API.Application.Interfaces.Email;
using System.Text;
using System.Text.Encodings.Web;

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

        public (string subject, string body) BuildPasswordReset(string firstName, string resetUrl)
        {
            const string subject = "Reset your XQARE password";
            var safeName = HtmlEncoder.Default.Encode(firstName ?? "there");
            var safeUrl = HtmlEncoder.Default.Encode(resetUrl);

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html>");
            sb.Append("<html><body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");
            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");
            sb.Append("<h2 style='color:#0f2a44;'>Reset your password</h2>");
            sb.Append($"<p>Hi {safeName},</p>");
            sb.Append("<p>We received a request to reset the password for your XQARE account.</p>");
            sb.Append($"<p style='text-align:center;margin:30px 0;'><a href='{safeUrl}' style='display:inline-block;background:#f59e0b;color:white;text-decoration:none;padding:14px 24px;border-radius:8px;font-weight:bold;'>Reset Password</a></p>");
            sb.Append("<p>This link expires in <strong>15 minutes</strong> and can be used only once.</p>");
            sb.Append("<p style='color:#777;'>If the button does not work, copy and paste this link into your browser:</p>");
            sb.Append($"<p style='word-break:break-all;color:#475569;'>{safeUrl}</p>");
            sb.Append("<p style='color:#777;'>If you did not request a password reset, you can safely ignore this email. Your current password will remain unchanged.</p>");
            sb.Append("<p>Best regards,<br><strong>Team XQARE</strong></p>");
            sb.Append("</div></body></html>");

            return (subject, sb.ToString());
        }

        public (string subject, string body) ContactUsCustomerTemplate(string firstName)
        {
            string subject = "We received your request - XQARE";

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html>");
            sb.Append("<body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");

            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");

            sb.Append("<h2 style='color:#333;'>Thank you for contacting us</h2>");

            sb.Append($"<p>Hi {firstName},</p>");

            sb.Append("<p>Thank you for reaching out to <strong>XQARE</strong>. We have received your request and our support team will review it shortly.</p>");

            sb.Append("<p>Our team usually responds within <strong>24 - 48 hours</strong>.</p>");

            sb.Append("<br>");

            sb.Append("<p style='color:#777;'>This is an automated confirmation email to let you know that your message has been received.</p>");

            sb.Append("<br>");

            sb.Append("<p>Best regards,<br><strong>Team XQARE</strong></p>");

            sb.Append("</div>");
            sb.Append("</body>");
            sb.Append("</html>");

            return (subject, sb.ToString());
        }

        public (string subject, string body) ContactUsSupportTemplate(string firstName, string email, string subject, string message)
        {
            subject = $"New Contact Request - {subject}";

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html>");
            sb.Append("<body style='font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;padding:30px;'>");

            sb.Append("<div style='max-width:500px;background:white;margin:auto;padding:30px;border-radius:8px;'>");

            sb.Append($"<h2 style='color:#333;'>{subject}</h2>");

            sb.Append("<p>You have received a new contact request from the website.</p>");

            sb.Append("<table style='width:100%;border-collapse:collapse;margin-top:20px;'>");

            sb.Append("<tr>");
            sb.Append("<td style='padding:8px;font-weight:bold;'>Name:</td>");
            sb.Append($"<td style='padding:8px;'>{firstName}</td>");
            sb.Append("</tr>");

            sb.Append("<tr>");
            sb.Append("<td style='padding:8px;font-weight:bold;'>Email:</td>");
            sb.Append($"<td style='padding:8px;'>{email}</td>");
            sb.Append("</tr>");

            sb.Append("<tr>");
            sb.Append("<td style='padding:8px;font-weight:bold;'>Message:</td>");
            sb.Append($"<td style='padding:8px;'>{message}</td>");
            sb.Append("</tr>");

            sb.Append("</table>");

            sb.Append("<br>");

            sb.Append("<p style='color:#777;'>Please respond to this request as soon as possible.</p>");

            sb.Append("<p>Best regards,<br><strong>XQARE Website</strong></p>");

            sb.Append("</div>");
            sb.Append("</body>");
            sb.Append("</html>");

            return (subject, sb.ToString());
        }
    }
}