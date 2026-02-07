import express from "express";
import serverless from "serverless-http";
import { NestFactory } from "@nestjs/core";
import { ExpressAdapter } from "@nestjs/platform-express";
import { AppModule } from "../src/app.module";

let cached: any;

async function bootstrap() {
  try {
    const expressApp = express();
    const app = await NestFactory.create(AppModule, new ExpressAdapter(expressApp));

    // copy any main.ts config here, e.g.
    // app.enableCors();
    // app.setGlobalPrefix("api");

    await app.init();
    return serverless(expressApp);
  } catch (err) {
    console.error("Nest bootstrap failed:", err);
    throw err;
  }
}

export default async function handler(req: any, res: any) {
  try {
    if (!cached) cached = await bootstrap();
    return cached(req, res);
  } catch (err) {
    console.error("Handler failed:", err);
    res.statusCode = 500;
    res.end("Internal Server Error");
  }
}
