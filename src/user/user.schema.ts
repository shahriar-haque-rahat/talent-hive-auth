import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
    @Prop({ required: true, maxlength: 100 })
    fullName: string;

    @Prop({ required: true, maxlength: 40 })
    userName: string;

    @Prop({ required: true, maxlength: 100 })
    email: string;

    @Prop({ required: true, maxlength: 255 })
    password: string;

    @Prop({ maxlength: 40, default: null })
    status?: string;

    @Prop({ maxlength: 40, default: null })
    role?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
