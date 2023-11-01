import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { APP_FILTER, APP_PIPE } from '@nestjs/core'
import { PrismaModule } from '@prisma/prisma.module'
import { ZodValidationPipe } from 'nestjs-zod'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { PrismaException } from './common/exceptions/prisma.exception'
import { AuthModule } from './modules/auth/auth.module'
import { UserModule } from './modules/user/user.module'
@Module({
  imports: [ConfigModule.forRoot(), PrismaModule, AuthModule, UserModule],
  controllers: [AppController],
  providers: [
    AppService,
    { provide: APP_PIPE, useClass: ZodValidationPipe },
    { provide: APP_FILTER, useClass: PrismaException }
  ]
})
export class AppModule {}
