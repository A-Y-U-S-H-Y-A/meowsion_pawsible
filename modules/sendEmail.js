import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // Your Gmail address
    pass: process.env.GMAIL_APP_PASSWORD // Your App Password
  }
});

export const sendOtpEmail = async (email, otp) => {
  const subject = 'Your Meowsion Pawsible OTP';

  const html = `
    <div style="font-family: Arial, sans-serif; font-size: 16px;">
      <p>Dear user,</p>
      <p>Your OTP for Meowsion Pawsible is:</p>
      <h2>${otp}</h2>
      <p>This OTP is valid for 10 minutes.</p>
      <p>If you didn’t request this, please ignore.</p>
      <br />
      <p>Regards,<br />Team</p>
    </div>
  `;

  await transporter.sendMail({
    from: 'Team Meowsion Pawsible',
    to: email,
    subject,
    html
  });
};

export const sendVerificationLinkEmail = async (email, token) => {
  const subject = 'Verify your Meowsion Pawsible account';

  const html = `
    <div style="font-family: Arial, sans-serif; font-size: 16px;">
      <p>Dear user,</p>
      <p>Click the link below to verify your account:</p>
      <a href="${process.env.FRONTEND_URL}/verify/${token}" style="color: blue;">
        Verify My Account
      </a>
      <p>This link is valid for 24 hours.</p>
      <br />
      <p>Regards,<br />Team Meowsion Pawsible</p>
    </div>
  `;

  await transporter.sendMail({
    from: 'Team Meowsion Pawsible',
    to: email,
    subject,
    html
  });
};

