import { Module } from '@nestjs/common'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { ConfigModule } from '@nestjs/config'
import { APP_FILTER, APP_PIPE } from '@nestjs/core'
import { ZodValidationPipe } from 'nestjs-zod'
import { UserModule } from './modules/user/user.module'
import { PrismaModule } from '@prisma/prisma.module'
import { AuthModule } from './modules/auth/auth.module'
import { PrismaException } from './common/exceptions/prisma.exception'

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
