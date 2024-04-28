import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { AccessTokenStrategy } from '../common/strategies';
import { APP_GUARD } from '@nestjs/core';
import { AccessTokenGuard } from '../common/guards';

@Module({
  imports: [JwtModule.register({}), PrismaModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    AccessTokenStrategy,
    // { provide: APP_GUARD, useClass: AccessTokenGuard },
  ],
})
export class AuthModule {}
