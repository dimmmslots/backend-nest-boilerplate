import { PrismaException } from '@/common/exceptions/prisma.exception'
import { JwtUtilService } from '@/utils/jwt.utils'
import { PrismaModule } from '@db/prisma.module'
import { PrismaService } from '@db/prisma.service'
import { faker } from '@faker-js/faker'
import { APP_FILTER } from '@nestjs/core'
import { JwtModule, JwtService } from '@nestjs/jwt'
import { Test, TestingModule } from '@nestjs/testing'
import { PrismaClient } from '@prisma/client'
import { compare, hash } from 'bcrypt'
import { AuthService } from './auth.service'
import env from '@/configs/env'
import { Request } from 'express'

describe('AuthService', () => {
  let authService: AuthService
  let prismaService: PrismaClient
  let jwtService: JwtService
  const password = 'password'
  let hashPassword: string
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthService, JwtUtilService, PrismaService, { provide: APP_FILTER, useClass: PrismaException }],
      imports: [JwtModule, PrismaModule]
    }).compile()

    authService = module.get<AuthService>(AuthService)
    prismaService = new PrismaClient()
    jwtService = module.get<JwtService>(JwtService)
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

  it('it should login local success', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser.username).toBe(username)

    const loginLocal = await authService.loginLocal({
      username: createUser.username,
      password: hashPassword
    })

    const user = await prismaService.user.findUnique({
      where: {
        username
      }
    })

    expect(user.username).toBe(username)

    expect(loginLocal).toStrictEqual(user)

    await prismaService.user.delete({
      where: {
        username
      }
    })
  })

  it('it should login local error', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser.username).toBe(username)

    await expect(async () => {
      return await authService.loginLocal({
        username: createUser.username,
        password: 'password1'
      })
    }).rejects.toThrow('Unauthorized')

    await prismaService.user.delete({
      where: {
        username
      }
    })
  })

  it('it should login jwt sucess', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser.username).toBe(username)

    const user = await prismaService.user.findUnique({
      where: {
        username
      }
    })
    expect(user.username).toBe(username)

    const loginJwt = await authService.loginJwt(user)

    const userAfterLogin = await prismaService.user.findUnique({
      where: {
        username
      },
      include: {
        session_token_user: true
      }
    })

    const { user: userJwt, access_token, refresh_token } = loginJwt

    delete user.password

    expect(userJwt).toStrictEqual(user)
    const { sub, username: usernameVerify } = await jwtService.verify(access_token, {
      secret: env.JWT_SECRET
    })

    const { sub: subRefreshToken, username: usernameVerifyRefreshToken } = await jwtService.verify(refresh_token, {
      secret: env.JWT_REFRESH_SECRET
    })

    expect({
      sub,
      username: usernameVerify
    }).toStrictEqual({
      sub: user.id,
      username: user.username
    })

    expect({
      sub: subRefreshToken,
      username: usernameVerifyRefreshToken
    }).toStrictEqual({
      sub: user.id,
      username: user.username
    })

    expect(access_token).toBe(userAfterLogin.session_token_user.access_token)
    expect(refresh_token).toBe(userAfterLogin.session_token_user.refresh_token)

    await prismaService.user.delete({
      where: {
        username
      }
    })
  })
  it('it should create new access token success', async () => {
    const username = faker.person.firstName()
    const createUser = await authService.registerUser({
      username,
      password: hashPassword
    })

    expect(createUser.username).toBe(username)

    const user = await prismaService.user.findUnique({
      where: {
        username
      }
    })

    expect(user.username).toBe(username)

    const loginJwt = await authService.loginJwt(user)

    const userAfterLogin = await prismaService.user.findUnique({
      where: {
        username
      },
      include: {
        session_token_user: true
      }
    })

    const { user: userJwt, access_token, refresh_token } = loginJwt

    delete user.password

    expect(userJwt).toStrictEqual(user)
    const { sub, username: usernameVerify } = await jwtService.verify(access_token, {
      secret: env.JWT_SECRET
    })

    const { sub: subRefreshToken, username: usernameVerifyRefreshToken } = await jwtService.verify(refresh_token, {
      secret: env.JWT_REFRESH_SECRET
    })

    expect({
      sub,
      username: usernameVerify
    }).toStrictEqual({
      sub: user.id,
      username: user.username
    })

    expect({
      sub: subRefreshToken,
      username: usernameVerifyRefreshToken
    }).toStrictEqual({
      sub: user.id,
      username: user.username
    })

    expect(access_token).toBe(userAfterLogin.session_token_user.access_token)
    expect(refresh_token).toBe(userAfterLogin.session_token_user.refresh_token)

    const req = {
      headers: {
        authorization: `Bearer ${access_token}`
      },
      user: {
        id: user.id,
        username: user.username
      }
    } as Request

    const createNewAccessToken = await authService.createNewAccessToken(req)
    const getUserAfterCreateNewAccessToken = await prismaService.user.findUnique({
      where: {
        username
      },
      include: {
        session_token_user: true
      }
    })

    expect(createNewAccessToken).toStrictEqual({
      access_token: getUserAfterCreateNewAccessToken.session_token_user.access_token
    })

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
