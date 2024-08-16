import { BadRequestException, Inject, Injectable, InternalServerErrorException } from '@nestjs/common';
import { User } from 'src/user/user.sql.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserRegisterDto } from './dto/user-register.dto';
import * as bcrypt from 'bcrypt';
import { MailerService } from '@nestjs-modules/mailer';
import { JwtService } from '@nestjs/jwt';
import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';

@Injectable()
export class AuthService {
    private readonly sevenDaysExpire = 7 * 24 * 60 * 60;
    private readonly hourExpire = 60 * 60;

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
}
