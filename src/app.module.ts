import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserController } from './user/user.controller';
import { UserService } from './user/user.service';
import { UserModule } from './user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import mysqlConfig from './config/mysql.config';
import { MailerModule } from '@nestjs-modules/mailer';
import { nodemailerConfig } from './config/nodemailer.config';
import { JwtModule } from '@nestjs/jwt';
import { jwtConfig } from './config/jwt.config';
import { CacheModule } from '@nestjs/cache-manager';
import { cacheConfig } from './config/cache.config';

@Module({
  imports: [
    AuthModule,
    UserModule,
    TypeOrmModule.forRoot(mysqlConfig),
    MailerModule.forRoot(nodemailerConfig),
    JwtModule.register(jwtConfig),
    CacheModule.register(cacheConfig)
  ],
  controllers: [AppController, UserController],
  providers: [AppService, UserService],
})
export class AppModule { }
