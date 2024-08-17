import { CACHE_MANAGER } from "@nestjs/cache-manager";
import { Cache } from 'cache-manager';
import { Inject, Injectable, InternalServerErrorException, NestMiddleware, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { NextFunction, Request, Response } from "express";
import { jwtConfig } from "src/config/jwt.config";
import { Session } from "src/types/auth.types";

export interface VerifyRequest extends Request {
    user: Session;
}

@Injectable()
export class VerifyMiddleware implements NestMiddleware {
    constructor(
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private jwtService: JwtService
    ) { }

    async use(req: VerifyRequest, res: Response, next: NextFunction) {
        try {
            const { authorization } = req.headers;

            const token = authorization && authorization?.split(' ')[1];

            if (!token) {
                throw new UnauthorizedException('Unauthorize Access');
            };

            const decoded = await this.jwtService.verify(token, {
                secret: jwtConfig.secret
            });

            if (!decoded) {
                throw new UnauthorizedException('Unauthorize Access');
            };

            const tokenFromCache = await this.cacheManager.get(`${decoded.id}_access_token`);

            if (!tokenFromCache) {
                throw new UnauthorizedException('Unauthorize Access');
            };

            const decodedFromCache = await this.jwtService.verify(tokenFromCache as string, {
                secret: jwtConfig.secret
            });

            if (!decodedFromCache || decodedFromCache?.id != decoded?.id) {
                throw new UnauthorizedException('Unauthorize Access');
            };

            req.user = decoded || {};

            next();
        }
        catch (error) {
            throw new InternalServerErrorException('Unauthorize Access5', {
                cause: new Error(),
                description: error.message,
            });
        }
    }
};