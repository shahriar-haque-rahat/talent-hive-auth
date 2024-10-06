import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
    @Prop({ required: true })
    fullName: string;

    @Prop({ required: true })
    userName: string;

    @Prop({ required: true })
    email: string;

    @Prop({ required: true })
    password: string;

    @Prop({ default: null })
    status?: string;

    @Prop({ default: null })
    role?: string;

    @Prop({ default: null })
    profileImage?: string;

    @Prop({ default: null })
    coverImage?: string;

    @Prop({ default: null })
    designation?: string;

    @Prop({ default: null })
    phoneNumber?: number;

    @Prop({ default: null })
    about?: string;

    @Prop({ default: null })
    facebookLink?: string;

    @Prop({ default: null })
    linkedInLink?: string;

    @Prop({ default: null })
    resumeLink?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
