import nodemailer from 'nodemailer';
import { SMTP_HOST, SMTP_PORT, MAIL_USER, MAIL_PASS } from '../config';

class EmailService {
    static async sendMail({from, to, subject, text, html}) {
        let transporter = nodemailer.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: false,
            auth: {
                user: MAIL_USER,
                pass: MAIL_PASS,
            }
        })
        
        let info = await transporter.sendMail({
            from, 
            to, 
            subject, 
            text, 
            html
        })
    }
}

export default EmailService;