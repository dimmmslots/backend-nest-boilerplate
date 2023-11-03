import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import env from '@/configs/env'
import { ResponseInterceptor } from './common/interceptors/response.interceptor'
import * as passport from 'passport'
import * as session from 'express-session'
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule)
  app.useGlobalInterceptors(new ResponseInterceptor())
  app.setGlobalPrefix('/api')
  // setting passport sesssion
  app.use(
    session({
      secret: 'test',
      resave: false,
      saveUninitialized: false
    })
  )
  app.use(passport.initialize())
  app.use(passport.session())
  const port = env.PORT || 3000
  await app.listen(port)
}
bootstrap()
