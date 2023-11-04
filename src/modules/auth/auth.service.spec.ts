import { PrismaException } from '@/common/exceptions/prisma.exception'
import { JwtUtilService } from '@/utils/jwt.utils'
import { PrismaModule } from '@db/prisma.module'
import { PrismaService } from '@db/prisma.service'
import { faker } from '@faker-js/faker'
import { APP_FILTER } from '@nestjs/core'
import { JwtModule } from '@nestjs/jwt'
import { Test, TestingModule } from '@nestjs/testing'
import { compare, hash } from 'bcrypt'
import { AuthService } from './auth.service'

describe('AuthService', () => {
  let authService: AuthService
  let prismaService: PrismaService
  const password = 'password'
  let hashPassword: string
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService, JwtUtilService, PrismaService, { provide: APP_FILTER, useClass: PrismaException }],
      imports: [JwtModule, PrismaModule]
    }).compile()

    authService = module.get<AuthService>(AuthService)
    prismaService = module.get<PrismaService>(PrismaService)
    hashPassword = await hash(password, 10)
  })

  // check if authservice is defined
  it('it should be defined authService', () => {
    expect(authService).toBeDefined()
  })

  it('it should be defined prismaService', () => {
    expect(prismaService).toBeDefined()
  })

  it('it should be password hash', async () => {
    expect(await compare(password, hashPassword)).toBe(true)
  })

  it('it should be user register success', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser).toStrictEqual({ username })

    await prismaService.user.delete({
      where: {
        username
      }
    })
  })
  it('it should be user register error', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser.username).toBe(username)

    await expect(async () => {
      return await authService.registerUser({
        username: createUser.username,
        password: hashPassword
      })
    }).rejects.toThrow('Unique constraint failed on the fields: (`username`)')

    await prismaService.user.delete({
      where: {
        username
      }
    })
  })

  afterAll((done) => {
    done()
  })
})
