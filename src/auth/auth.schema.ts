import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class AuthCache extends Document {
    @Prop({ required: true })
    userId: string;

    @Prop()
    accessToken: string;

    @Prop()
    refreshToken: string;

    @Prop()
    emailActivationToken: string;

    @Prop()
    resetPasswordToken: string;

    @Prop({ default: Date.now, expires: '1h' }) // TTL for access token
    createdAt: Date;

    @Prop({ default: Date.now, expires: '7d' }) // TTL for refresh token
    createdAtRefresh: Date;
}

export const AuthCacheSchema = SchemaFactory.createForClass(AuthCache);
