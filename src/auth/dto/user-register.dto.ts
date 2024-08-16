import { IsEmail, IsNotEmpty, IsOptional, IsString, MaxLength, MinLength } from "class-validator";

export class UserRegisterDto {
    readonly id: number;

    @IsNotEmpty({ message: 'Full Name is required' })
    @IsString({ message: 'Full Name must be a string' })
    @MaxLength(100, { message: 'Full Name cannot exceed 100 characters' })
    readonly fullName: string;

    @IsNotEmpty({ message: 'Username is required' })
    @IsString({ message: 'Username must be a string' })
    @MaxLength(40, { message: 'Username cannot exceed 40 characters' })
    readonly userName: string;

    @IsNotEmpty({ message: 'Email is required' })
    @IsEmail({}, { message: 'Email must be valid' })
    @MaxLength(100, { message: 'Email cannot exceed 100 characters' })
    readonly email: string;

    @IsNotEmpty({ message: 'Password is required' })
    @IsString({ message: 'Password must be a string' })
    @MinLength(6, { message: 'Password must be at least 6 characters long' })
    @MaxLength(40, { message: 'Password cannot exceed 40 characters' })
    readonly password: string;

    @IsOptional()
    @IsString({ message: 'Activation Code must be a string' })
    @MaxLength(40, { message: 'Activation Code cannot exceed 40 characters' })
    readonly activationCode?: string;

    @IsOptional()
    @IsString({ message: 'Status must be a string' })
    @MaxLength(40, { message: 'Status cannot exceed 40 characters' })
    readonly status?: string;

    @IsOptional()
    @IsString({ message: 'Role must be a string' })
    @MaxLength(40, { message: 'Role cannot exceed 40 characters' })
    readonly role?: string;
}