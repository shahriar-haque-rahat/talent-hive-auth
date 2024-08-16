import * as dotenv from 'dotenv';
dotenv.config();

export const jwtConfig = {
    global: true,
    secret: process.env.JWT_SECRET_KEY,
    signOptions: {
        expiresIn: '60s',
    }
};
