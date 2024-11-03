import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  });

  // app.setGlobalPrefix(process.env.GLOBAL_PREFIX || 'v1/api');
  await app.listen(process.env.PORT || 8081);
}
bootstrap();
