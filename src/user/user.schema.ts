import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
    @Prop({ required: true, maxlength: 40 })
    uid: string;

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

    @Prop({ default: new Date() })
    createdOn?: Date;

    @Prop({ default: new Date() })
    modifiedOn?: Date;
}

// Create the schema for the User class
export const UserSchema = SchemaFactory.createForClass(User);

// Optional: Pre-save hook to automatically update the modifiedOn field
UserSchema.pre('save', function(next) {
    this.modifiedOn = new Date();
    next();
});
