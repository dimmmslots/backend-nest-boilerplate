import { Injectable, UnauthorizedException } from '@nestjs/common'
import { User } from '@prisma/client'
import { PrismaService } from '@prisma/prisma.service'
import { compare, hash } from 'bcrypt'
import { LoginDTO } from './dtos/login.dto'
import { RegisterUserDTO } from './dtos/register.dto'
import { PayloadAccessToken, TypeToken } from '@/types/token'
import { JwtStrategy } from './strategies/jwt.strategy'
import { JwtService } from '@nestjs/jwt'
import env from '@/configs/env'
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
        email,
        username,
        password: hashed
      },
      select: {
        email: true,
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

  async loginJwt(payload: LoginDTO) {
    const { username, password } = payload
    const user = await this.prismaService.user.findUnique({ where: { username } })
    if (!user) throw new UnauthorizedException()
    const passwordMatches = await compare(password, user.password)
    if (!passwordMatches) throw new UnauthorizedException()
    return user
  }

  protected async createToken(payload: PayloadAccessToken): Promise<TypeToken> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.sign(payload, {
        secret: env.JWT_SECRET
      }),
      this.jwtService.sign(payload, {
        secret: env.JWT_REFRESH_SECRET
      })
    ])

    return {
      access_token,
      refresh_token
    }
  }
}
