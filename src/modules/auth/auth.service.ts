import env from '@/configs/env'
import { PayloadAccessToken, ResponseToken } from '@/types/jwt'
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { User } from '@prisma/client'
import { PrismaService } from '@prisma/prisma.service'
import { compare, hash } from 'bcrypt'
import { LoginDTO } from './dtos/login.dto'
import { RegisterUserDTO } from './dtos/register.dto'
@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService
  ) {}

  async registerUser(payload: RegisterUserDTO) {
    const { email, username, password } = payload
    const hashed = await hash(password, 10)
    return await this.prismaService.user.create({
      data: {
        username,
        password: hashed
      },
      select: {
        username: true
      }
    })
  }

  async loginLocal(payload: LoginDTO): Promise<User> {
    const { username, password } = payload
    const user = await this.prismaService.user.findUnique({ where: { username } })
    if (!user) throw new UnauthorizedException()
    const passwordMatches = await compare(password, user.password)
    if (!passwordMatches) throw new UnauthorizedException()
    return user
  }

  async loginJwt(payload: User): Promise<ResponseToken> {
    const { username } = payload
    const user = await this.prismaService.user.findUnique({ where: { username: username } })
    return await this.createToken({ sub: payload.id, username: payload.username }, user)
  }

  async logout(req: any) {
    req.session.destroy()
    return 'ok'
  }

  protected async createToken(payload: PayloadAccessToken, user: User): Promise<ResponseToken> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.sign(payload, {
        secret: env.JWT_SECRET
      }),
      this.jwtService.sign(payload, {
        secret: env.JWT_REFRESH_SECRET
      })
    ])

    // create or update token
    await this.prismaService.session_token_user.upsert({
      where: {
        userId: user.id
      },
      create: {
        userId: user.id,
        access_token,
        refresh_token
      },
      update: {
        access_token,
        refresh_token
      }
    })

    delete user.password
    return {
      user,
      access_token,
      refresh_token
    }
  }
}
