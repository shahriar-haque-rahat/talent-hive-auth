import { MailerOptions } from '@nestjs-modules/mailer';
import * as dotenv from 'dotenv';
dotenv.config();

export const nodemailerConfig: MailerOptions = {
    transport: {
        host: process.env.EMAIL_HOST,
        port: +process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASS,
        },
        secure: true,
        service: 'GMAIL',
    }
};
