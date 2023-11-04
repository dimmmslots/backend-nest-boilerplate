import { Test, TestingModule } from '@nestjs/testing'
import { AuthService } from './auth.service'
import { JwtModule } from '@nestjs/jwt'
import { PrismaModule } from '@db/prisma.module'
import { JwtUtilService } from '@/utils/jwt.utils'

describe('AuthService', () => {
  let authService: AuthService

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService, JwtUtilService],
      imports: [JwtModule, PrismaModule]
    }).compile()

    authService = module.get<AuthService>(AuthService)
  })

  // check if authservice is defined
  it('Should be defined', () => {
    expect(authService).toBeDefined()
  })

  // it('Should register success', async () => {
  //   const createUser = await authService.registerUser({
  //     username: 'farriq1',
  //     password: 'farriq'
  //   })
  //   expect(createUser).toStrictEqual({ username: 'farriq1' })
  // })
})
