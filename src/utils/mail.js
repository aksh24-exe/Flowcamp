import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendEmail = async (options) => {
  const mailGenerate = new Mailgen({
    theme: "default",
    product: {
      name: "Flowcamp",
      link: "https://flowcamp.vercel.app",
    },
  });
  const emailTextual = mailGenerate.generatePlaintext(options.mailgenContent);

  const emailHtml = mailGenerate.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_SMTP_USER,
      pass: process.env.MAILTRAP_SMTP_PASS,
    },
  });

  const mail = {
    from: "mail.flowcamp@exmaple.com",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error("Email Service failed due to credentials", error);

    throw error;
  }
};
const emailVerificationMailgenContent = (username, verficationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to Flowcamp! We're very excited to have you on board.",
      action: {
        instructions: "To get started with Flowcamp, please click here:",
        button: {
          color: "#22BC66",
          text: "Verify Email",
          link: verficationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};
const forgetPasswordMailgenContent = (username, passwordUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset your password.",
      action: {
        instructions: "To reset your password, please click here:",
        button: {
          color: "#22BC66",
          text: "Reset Email",
          link: passwordUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

export {
  emailVerificationMailgenContent,
  forgetPasswordMailgenContent,
  sendEmail,
};
