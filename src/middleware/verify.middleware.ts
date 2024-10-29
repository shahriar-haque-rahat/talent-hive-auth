import { Inject, Injectable, InternalServerErrorException, NestMiddleware, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { NextFunction, Request, Response } from "express";
import { jwtConfig } from "src/config/jwt.config";
import { Session } from "src/types/auth.types";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { AuthCache } from "src/auth/auth.schema";

export interface VerifyRequest extends Request {
    user: Session;
}

@Injectable()
export class VerifyMiddleware implements NestMiddleware {
    constructor(
        private jwtService: JwtService,
        @InjectModel(AuthCache.name) private authCacheModel: Model<AuthCache>
    ) { }

    async use(req: VerifyRequest, res: Response, next: NextFunction) {
        try {
            const { authorization } = req.headers;
            const token = authorization && authorization.split(' ')[1];

            if (!token) {
                throw new UnauthorizedException('Unauthorized Access');
            }

            const decoded = await this.jwtService.verify(token, {
                secret: jwtConfig.secret,
            });

            if (!decoded) {
                throw new UnauthorizedException('Unauthorized Access');
            }

            const cacheData = await this.authCacheModel.findOne({ userId: decoded.id }).exec();

            if (!cacheData || token !== cacheData.accessToken) {
                throw new UnauthorizedException('Unauthorized Access');
            }

            const decodedFromCache = await this.jwtService.verify(cacheData.accessToken, {
                secret: jwtConfig.secret,
            });

            if (!decodedFromCache || decodedFromCache.id !== decoded.id) {
                throw new UnauthorizedException('Unauthorized Access');
            }

            req.user = decoded || {};
            next();
        } catch (error) {
            throw new InternalServerErrorException('Unauthorized Access', {
                cause: new Error(),
                description: error.message,
            });
        }
    }
}
