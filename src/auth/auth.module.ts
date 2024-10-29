import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/user/user.schema';
import { AuthCache, AuthCacheSchema } from './auth.schema';
import { VerifyMiddleware } from 'src/middleware/verify.middleware';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    MongooseModule.forFeature([{ name: AuthCache.name, schema: AuthCacheSchema }])
  ],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(VerifyMiddleware)
      .forRoutes({ path: 'auth/logout', method: RequestMethod.POST });
  }
}
