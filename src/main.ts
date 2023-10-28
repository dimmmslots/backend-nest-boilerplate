import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import { PORT } from '@/configs/env'

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule)
  app.setGlobalPrefix('/api')
  const port = PORT || 3000

  await app.listen(port)
}
bootstrap()
