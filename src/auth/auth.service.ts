import {
    BadRequestException,
    Inject,
    Injectable,
    InternalServerErrorException,
    NotFoundException,
    UnauthorizedException
} from '@nestjs/common';
import { UserRegisterDto } from './dto/user-register.dto';
import * as bcrypt from 'bcrypt';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/user/user.schema';
import { Session } from 'src/types/auth.types';
import { UserVerifyDto } from './dto/user-verify.dto';
import { UserRefreshDto } from './dto/user-refresh.dto';
import { jwtConfig } from 'src/config/jwt.config';
import { UserLoginDto } from './dto/user-login.dto';
import { VerifyRequest } from 'src/middleware/verify.middleware';
import { UserForgotPasswordDto } from './dto/user-forgotpassword.dto';
import { UserResetPasswordDto } from './dto/user-resertpassword.dto';
import { AuthCache } from './auth.schema';

@Injectable()
export class AuthService {
    private readonly sevenDaysExpire = 7 * 24 * 60 * 60 * 1000;
    private readonly hourExpire = 60 * 60 * 1000;

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        @InjectModel(AuthCache.name) private authCacheModel: Model<AuthCache>,
        private jwtService: JwtService,
        private mailerService: MailerService
    ) { }

    private async sendMail(message: string, to: string, subject?: string) {
        await this.mailerService.sendMail({
            from: 'Shahriar Haque <shahriar.haque.1011@gmail.com>',
            to,
            subject: subject || 'Email Confirmation!',
            text: message,
        });
    }

    private accessAndRefreshToken(payload: Session) {
        try {
            const accessToken = this.jwtService.sign(payload, {
                expiresIn: '1h'
            });
            const refreshToken = this.jwtService.sign(payload, {
                expiresIn: '7d'
            });

            return { success: true, accessToken, refreshToken };
        } catch (error) {
            throw new BadRequestException('Invalid token');
        }
    }

    private async saveToken(userId: string, accessToken: string, refreshToken: string) {
        await this.authCacheModel.findOneAndUpdate(
            { userId },
            { accessToken, refreshToken },
            { upsert: true, new: true }
        ).exec();
    }

    async session(session: Session) {
        try {
            const { id } = session || {};
            const user = await this.userModel.findById(id).exec();

            if (!user) {
                throw new NotFoundException('User not found');
            }

            return { success: true, data: user };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to get session data'
            );
        }
    }

    async register(userRegisterDto: UserRegisterDto) {
        try {
            const { email, password, ...restUser } = userRegisterDto;

            const isExist = await this.userModel.findOne({ email }).exec();

            if (isExist) {
                throw new BadRequestException('User Already Registered', {
                    cause: new Error(),
                    description: 'User already registered with this email',
                });
            }

            const hashedPass = await bcrypt.hash(password, 10);

            const user = new this.userModel({
                email,
                password: hashedPass,
                ...restUser,
            });

            const saveResponse = await user.save();

            const payload = {
                id: saveResponse?.id,
                email,
                fullName: saveResponse?.fullName
            };

            const token = await this.jwtService.signAsync(payload, {
                expiresIn: '1h',
            });

            await this.authCacheModel.findOneAndUpdate(
                { userId: saveResponse?.id },
                { emailActivationToken: token },
                { upsert: true }
            ).exec();

            await this.sendMail(
                `Click to confirm ${process.env.CLIENT_URL}/login?token=${token}`,
                email
            );

            return saveResponse;
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to register'
            );
        }
    }

    async accountActive(userVerifyDto: UserVerifyDto) {
        try {
            const { token } = userVerifyDto || {};

            const decoded = await this.jwtService.verify(token, {
                secret: process.env.JWT_SECRET_KEY,
            });

            if (!decoded) {
                throw new UnauthorizedException('Unauthorize access');
            }

            const { id } = decoded;

            const currentDate = Math.floor(Date.now() / 1000);

            const isExpired = decoded.exp < currentDate;

            if (isExpired) {
                throw new UnauthorizedException('Token Expired!');
            }

            const cacheData = await this.authCacheModel.findOne({ userId: id }).exec();

            if (!cacheData || token !== cacheData.emailActivationToken) {
                throw new UnauthorizedException('Unauthorize access');
            }

            const user = await this.userModel.findById(id).exec();

            if (!user || user.status === 'active') {
                throw new BadRequestException('User already active');
            }

            await this.userModel.findByIdAndUpdate(id, { status: 'active' }).exec();

            const payload = {
                id: decoded?.id,
                email: decoded?.email,
                fullName: decoded?.fullName
            };

            const { accessToken, refreshToken } = this.accessAndRefreshToken(payload);

            await this.saveToken(decoded?.id, accessToken, refreshToken);

            await this.authCacheModel.deleteOne({ userId: id }).exec();

            return { success: true, accessToken, refreshToken, user: payload };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to activate account'
            );
        }
    }

    async tokenRefresh(userRefreshDto: UserRefreshDto) {
        try {
            const { refreshToken } = userRefreshDto;

            const decoded = await this.jwtService.verify(refreshToken, {
                secret: jwtConfig.secret,
            });

            if (!decoded) {
                throw new UnauthorizedException('Unauthorize Access');
            }

            const cacheData = await this.authCacheModel.findOne({ userId: decoded.id }).exec();

            if (!cacheData || refreshToken !== cacheData.refreshToken) {
                throw new UnauthorizedException('Unauthorize Access');
            }

            const decodedFromCache = await this.jwtService.verify(cacheData.refreshToken, {
                secret: jwtConfig.secret,
            });

            const currentDate = Math.floor(Date.now() / 1000);
            const isExpired = decodedFromCache?.exp < currentDate;

            if (!decodedFromCache || isExpired) {
                throw new UnauthorizedException('Unauthorize Access');
            }

            const payload = {
                id: decodedFromCache?.id,
                email: decodedFromCache?.email,
                fullName: decodedFromCache?.fullName
            };

            const { accessToken, refreshToken: newRefreshToken } = this.accessAndRefreshToken(payload);

            await this.saveToken(decodedFromCache?.id, accessToken, newRefreshToken);

            return { success: true, accessToken, refreshToken: newRefreshToken };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to refresh token'
            );
        }
    }

    async login(userLoginDto: UserLoginDto) {
        try {
            const { email, password } = userLoginDto;

            const user = await this.userModel.findOne({ email }).exec();

            if (!user) {
                throw new NotFoundException('User not found');
            }

            if (user.status !== 'active') {
                throw new UnauthorizedException('User not active!');
            }

            const correctPassword = await bcrypt.compare(password, user.password);

            if (!correctPassword) {
                throw new UnauthorizedException('Invalid password');
            }

            const payload: Session = {
                id: `${user.id}`,
                email: user.email,
                fullName: user.fullName
            };

            const { accessToken, refreshToken } = this.accessAndRefreshToken(payload);

            await this.saveToken(user.id, accessToken, refreshToken);

            return { success: true, accessToken, refreshToken };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to login'
            );
        }
    }

    async logout(req: VerifyRequest) {
        try {
            const user: Session = req.user;

            await this.authCacheModel.deleteOne({ userId: user?.id }).exec();

            return { success: true, status: true };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to logout'
            );
        }
    }

    async forgotPassword(userForgotPasswordDto: UserForgotPasswordDto) {
        try {
            const { email } = userForgotPasswordDto;

            const user = await this.userModel.findOne({ email }).exec();

            if (!user) {
                throw new NotFoundException('User does not exist.');
            }

            if (user?.status !== 'active') {
                throw new BadRequestException('User account not activated!');
            }

            const payload = {
                id: user.id,
                email: user.email
            };

            const token = this.jwtService.sign(payload, {
                expiresIn: '1h'
            });

            await this.authCacheModel.findOneAndUpdate(
                { userId: user.id },
                { resetPasswordToken: token },
                { upsert: true }
            ).exec();

            const resetPasswordLink = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

            await this.sendMail(
                `Click the link below to reset your password = ${resetPasswordLink}`,
                email,
                `Reset Password`
            );

            return {
                success: true,
                message: `Password reset link sent`
            };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to process password reset request',
            );
        }
    }

    async resetPassword(userResetPasswordDto: UserResetPasswordDto) {
        try {
            const { token, newPassword } = userResetPasswordDto;

            const decoded = await this.jwtService.verify(token, {
                secret: jwtConfig.secret
            });

            const currentDate = Math.floor(Date.now() / 1000);
            const isExpired = decoded.exp < currentDate;

            if (isExpired) {
                throw new BadRequestException('Token expired');
            }

            const cacheData = await this.authCacheModel.findOne({ userId: decoded.id }).exec();

            if (!cacheData || token !== cacheData.resetPasswordToken) {
                throw new BadRequestException('Invalid token');
            }

            const user = await this.userModel.findById(decoded.id).exec();

            if (!user) {
                throw new NotFoundException('User not found.');
            }

            const hashedPass = await bcrypt.hash(newPassword, 10);

            await this.userModel.findByIdAndUpdate(decoded.id, {
                password: hashedPass,
                updatedAt: new Date()
            }).exec();

            await this.authCacheModel.deleteOne({ userId: decoded.id }).exec();

            return {
                success: true,
                message: 'Password changed'
            };
        } catch (error) {
            throw new InternalServerErrorException(
                error.message || 'Failed to reset password',
            );
        }
    }
}
