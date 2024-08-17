import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class UserLoginDto {
    @IsNotEmpty({ message: 'Email not provided' })
    @IsEmail()
    email: string;

    @IsNotEmpty({ message: 'Password not provided' })
    @IsString({ message: 'Password must be a string' })
    password: string;
}
