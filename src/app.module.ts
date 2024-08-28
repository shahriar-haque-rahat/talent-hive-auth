import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose'; 
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { nodemailerConfig } from './config/nodemailer.config';
import { JwtModule } from '@nestjs/jwt';
import { jwtConfig } from './config/jwt.config';
import { CacheModule } from '@nestjs/cache-manager';
import { cacheConfig } from './config/cache.config';
import mongoConfig from './config/mongodb.config'; 

@Module({
  imports: [
    MongooseModule.forRoot(mongoConfig.uri), 
    AuthModule,
    UserModule,
    MailerModule.forRoot(nodemailerConfig),
    JwtModule.register(jwtConfig),
    CacheModule.register(cacheConfig),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
