import dotenv from 'dotenv';

dotenv.config();

export const {
    APP_NAME,
    APP_PORT,
    DEBUG_MODE,
    DB_URL,
    JWT_SECRET,
    REFRESH_SECRET,
    RESET_SECRET,
    CLIENT_APP_URL,
    SMTP_HOST,
    SMTP_PORT,
    MAIL_USER,
    MAIL_PASS
} = process.env;