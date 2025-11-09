// utils/mailer.js
const { Resend } = require('resend');

// Khởi tạo Resend
const resend = new Resend(process.env.RESEND_API_KEY);
const appBaseUrl = process.env.APP_BASE_URL || 'http://localhost:3300';
const fromEmail = 'onboarding@resend.dev'; // Thay bằng email đã xác thực của bạn

/**
 * Tạo Template Email HTML (CHỈ DÙNG CHO BẢNG TIN)
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
        
        ${post.id ? `<a href="${postUrl}" class="button">Xem bài đăng</a>` : ''}
      </div>
    </body>
    </html>
  `;
}

/**
 * Hàm gửi email CHUNG
 * (Dùng cho cả Bảng tin và Báo giá)
 * SỬA: Thêm 'attachment' và 'replyTo'
 */
async function sendNewPostEmail(post, recipientEmails, attachment = null, replyTo = null) {
  if (!recipientEmails || recipientEmails.length === 0) {
    console.log('[Mailer] Không có email nào để gửi.');
    return;
  }
  
  // Tên bài đăng hoặc Tiêu đề báo giá
  const subject = post.title;
  
  // QUAN TRỌNG:
  // - Nếu 'post.content' đã có (từ Báo giá), dùng nó.
  // - Nếu không, tạo nó (từ Bảng tin).
  const emailHtml = post.content ? post.content : createEmailTemplate(post);

  try {
    console.log(`[Mailer] Bắt đầu gửi email "${subject}" đến ${recipientEmails.length} người...`);
    
    // SỬA: Thêm 'attachments' và 'reply_to'
    const payload = {
      from: `Hệ thống CTKM <${fromEmail}>`,
      to: recipientEmails,
      subject: subject,
      html: emailHtml,
      attachments: attachment ? [attachment] : undefined, // <-- ĐÃ THÊM
      reply_to: replyTo || undefined // <-- ĐÃ THÊM
    };

    const { data, error } = await resend.emails.send(payload);

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