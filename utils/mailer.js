// utils/mailer.js
const { Resend } = require('resend');

// Khởi tạo Resend
const resend = new Resend(process.env.RESEND_API_KEY);
const appBaseUrl = process.env.APP_BASE_URL || 'http://localhost:3300';
const fromEmail = 'onboarding@resend.dev'; // Thay bằng email đã xác thực của bạn

/**
 * Tạo Template Email HTML
 * Dùng inline-styles để tương thích với Gmail, Outlook...
 */
function createEmailTemplate(post) {
  const postUrl = `${appBaseUrl}/newsfeed/post/${post.id}`;
  
  return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { width: 90%; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .header { font-size: 24px; font-weight: bold; color: #0d6efd; }
        .content { margin-top: 20px; font-size: 16px; }
        .content img { max-width: 100%; height: auto; }
        .button { display: inline-block; margin-top: 25px; padding: 12px 20px; background-color: #0d6efd; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">${post.title}</div>
        ${post.subtitle ? `<p style="font-size: 18px; color: #6c757d;">${post.subtitle}</p>` : ''}
        
        <div class="content">
          ${post.content}
        </div>
        
        <a href="${postUrl}" class="button">Xem bài đăng</a>
      </div>
    </body>
    </html>
  `;
}

/**
 * Hàm gửi email chính
 * (Không 'await' hàm này trong server.js để tránh block response)
 */
async function sendNewPostEmail(post, recipientEmails) {
  if (!recipientEmails || recipientEmails.length === 0) {
    console.log('[Mailer] Không có email nào để gửi.');
    return;
  }
  
  // Tên bài đăng làm tiêu đề email
  const subject = `[Thông báo mới] ${post.title}`;
  
  // Tạo HTML
  const emailHtml = createEmailTemplate(post);

  try {
    console.log(`[Mailer] Bắt đầu gửi email "${subject}" đến ${recipientEmails.length} người...`);
    
    const { data, error } = await resend.emails.send({
      from: `Hệ thống CTKM <${fromEmail}>`,
      to: recipientEmails, // Resend hỗ trợ gửi hàng loạt
      subject: subject,
      html: emailHtml,
    });

    if (error) {
      console.error('[Mailer] Lỗi khi gửi:', error);
      return;
    }

    console.log(`[Mailer] Gửi thành công! ID: ${data.id}`);
  } catch (error) {
    console.error('[Mailer] Lỗi nghiêm trọng:', error.message);
  }
}

module.exports = { sendNewPostEmail };