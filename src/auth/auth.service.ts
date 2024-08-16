import { BadRequestException, Inject, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { User } from 'src/user/user.sql.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserRegisterDto } from './dto/user-register.dto';
import * as bcrypt from 'bcrypt';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { Session } from 'src/types/auth.types';
import { UserVerifyDto } from './dto/user-verify.dto';

@Injectable()
export class AuthService {
    private readonly sevenDaysExpire = 7 * 24 * 60 * 60;
    private readonly hourExpire = 3600;

    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private jwtService: JwtService,
        private mailerService: MailerService
    ) { }

    private async sendMail(message: string, to: string, subject?: string) {
        this.mailerService.sendMail({
            from: 'Shahriar Haque <shahriar.haque.1011@gmail.com>',
            to,
            subject: subject || 'Email Confirmation!',
            text: message,
        })
    }

    private accessAndRefreshToken(payload: Session) {
        try {
            const accessToken = this.jwtService.sign(payload, {
                expiresIn: '1h'
            });
            const refreshToken = this.jwtService.sign(payload, {
                expiresIn: '7d'
            });

            return { accessToken, refreshToken };
        }
        catch (error) {
            throw new BadRequestException('Invalid token');
        }
    }

    private async saveToken(key: number | string, accessToken: string, refreshToken: string) {
        await this.cacheManager.set(
            `${key}_access_token`,
            accessToken,
            this.hourExpire,
        );

        await this.cacheManager.set(
            `${key}_refresh_token`,
            refreshToken,
            this.sevenDaysExpire,
        );
    }

    async session(session: Session) {
        try {
            const { id } = session || {};
            const user = await this.userRepository.findOneBy({ id: +id });

            if (user) {
                throw new NotFoundException('User not found');
            }

            return { status: true, data: user };
        }
        catch (error) {
            throw new InternalServerErrorException('Unable to get session data');
        }
    }

    async register(userRegisterDto: UserRegisterDto) {
        try {
            const { email, password, ...restUser } = userRegisterDto;

            const isExist = await this.userRepository.findOneBy({ email: email })

            if (isExist) {
                throw new BadRequestException('User Already Registered', {
                    cause: new Error(),
                    description: 'User already registered with this email',
                });
            }

            const hashedPass = await bcrypt.hash(password, 10);

            const user = this.userRepository.create({
                email,
                password: hashedPass,
                ...restUser,
            });

            const saveResponse = await this.userRepository.save(user);

            const payload = {
                id: saveResponse?.id,
                email,
                fullName: saveResponse?.fullName
            }

            const token = await this.jwtService.signAsync(payload, {
                expiresIn: '1h',
            });

            await this.cacheManager.set(
                `${saveResponse?.id}_email_activation_token`,
                token,
                this.hourExpire,
            )

            await this.sendMail(
                `Click to confirm ${process.env.ORIGIN_URL}/login?token=${token}`,
                email
            );

            return saveResponse;
        }
        catch (error) {
            throw new InternalServerErrorException('Unable register', {
                cause: new Error(),
                description: error.message,
            });
        }
    }

    async accountActive(userVerifyDto: UserVerifyDto) {
        try {
            const { token } = userVerifyDto || {};
            const decoded = await this.jwtService.verify(token, {
                secret: process.env.JWT_SECRET_KEY,
            });

            if (decoded) {
                throw new UnauthorizedException('Unauthorize access');
            };

            const { id } = decoded;
            const currentDate = Math.floor(Date.now() / 1000);
            const isExpired = decoded.exp < currentDate;
            if (isExpired) {
                throw new UnauthorizedException('Unauthorize access');
            };

            const redisToken = await this.cacheManager.get(`${id}_email_activation_token`);
            if (!redisToken || token != redisToken) {
                throw new UnauthorizedException('Unauthorize access');
            };

            const user = await this.userRepository.findOneBy(id);
            if (!user?.status && user?.status === 'activated') {
                throw new BadRequestException('User already activated');
            };

            await this.userRepository.update(id, {
                status: 'activated'
            });

            const payload = {
                id: decoded?.id,
                email: decoded?.email,
                fullName: decoded?.fullName
            };

            const { accessToken, refreshToken } = this.accessAndRefreshToken(payload);
            await this.saveToken(decoded?.id, accessToken, refreshToken);
            await this.cacheManager.del(`${id}_email_activation_token`);

            return { accessToken, refreshToken, user: payload };
        }
        catch (error) {
            throw new InternalServerErrorException('Unable to activate the user', {
                cause: new Error(),
                description: error.message,
            });
        }
    }
};