// hash.js
const bcrypt = require('bcryptjs');

async function createHash() {
  const password = '123';
  const saltRounds = 10; // Giống như trong server.js

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    console.log(`Mật khẩu: ${password}`);
    console.log('Chuỗi hash (để dán vào Supabase):');
    console.log(hashedPassword);
    
  } catch (err) {
    console.error('Lỗi khi băm mật khẩu:', err);
  }
}

createHash();