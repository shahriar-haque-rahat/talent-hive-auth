import { Body, Controller, Get, Post, Put, Req, UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserRegisterDto } from './dto/user-register.dto';
import { VerifyRequest } from 'src/middleware/verify.middleware';
import { UserRefreshDto } from './dto/user-refresh.dto';
import { UserVerifyDto } from './dto/user-verify.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { UserForgotPasswordDto } from './dto/user-forgotpassword.dto';
import { UserResetPasswordDto } from './dto/user-resertpassword.dto';
import { User } from 'src/user/user.schema';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Get('session')
    @UsePipes(new ValidationPipe())
    session(@Req() req: VerifyRequest) {
        const session = req.user;
        return this.authService.session(session);
    }

    @Post('register')
    @UsePipes(new ValidationPipe())
    register(@Body() userRegisterDto: UserRegisterDto): Promise<User> {
        return this.authService.register(userRegisterDto);
    }

    @Post('refresh')
    @UsePipes(new ValidationPipe())
    refresh(@Body() UserRefreshDto: UserRefreshDto) {
        return this.authService.tokenRefresh(UserRefreshDto);
    }

    @Put('activate-account')
    activateAccount(@Body() UserVerifyDto: UserVerifyDto) {
        return this.authService.accountActive(UserVerifyDto);
    }

    @Post('login')
    login(@Body() UserLoginDto: UserLoginDto) {
        return this.authService.login(UserLoginDto);
    }

    @Post('logout')
    logout(@Req() req: VerifyRequest) {
        return this.authService.logout(req);
    }

    @Post('forgot-password')
    @UsePipes(new ValidationPipe())
    forgotPassword(
        @Body() UserForgotPasswordDto: UserForgotPasswordDto,
    ) {
        return this.authService.forgotPassword(UserForgotPasswordDto);
    }

    @Post('reset-password')
    @UsePipes(new ValidationPipe())
    resetPassword(
        @Body() UserResetPasswordDto: UserResetPasswordDto,
    ) {
        return this.authService.resetPassword(UserResetPasswordDto);
    }
}
