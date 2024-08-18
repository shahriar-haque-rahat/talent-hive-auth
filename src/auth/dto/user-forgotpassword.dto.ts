import { IsEmail, IsNotEmpty } from 'class-validator';

export class UserForgotPasswordDto {
    @IsNotEmpty()
    @IsEmail()
    readonly email: string;
}
