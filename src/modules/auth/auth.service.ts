import env from '@/configs/env'
import { DecodedJWT, PayloadAccessToken, ResponseToken } from '@/types/jwt'
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
    const { username, password } = payload
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
    return await this.createToken(user)
  }

  /**
   * logout local session
   * @param req request
   */
  async logout(req: any) {
    req.session.destroy()
  }

  async logoutJwt(req: any): Promise<{ message: string }> {
    req.session.destroy()

    const authorizationHeader = req.headers.authorization
    if (!authorizationHeader) {
      return { message: "You aren't signed in yet." }
    }

    const [type, token] = authorizationHeader.split(' ')

    if (type !== 'Bearer' || !token) {
      return { message: "You aren't signed in yet." }
    }

    try {
      const decoded = this.jwtService.decode(token) as DecodedJWT
      const userSession = await this.prismaService.session_token_user.findUnique({
        where: { userId: decoded.sub, access_token: token }
      })

      if (!userSession) {
        return { message: "You aren't signed in yet." }
      }

      await this.prismaService.session_token_user.delete({
        where: { userId: decoded.sub, access_token: token }
      })

      return { message: 'You have logged out successfully' }
    } catch (error) {
      // Handle any potential errors, such as invalid tokens or database issues.
      // Log the error for further investigation.
      return { message: 'An error occurred during logout' }
    }
  }

  /**
   * create token helper
   * @param user User
   * @returns Promise ResponseToken
   */
  protected async createToken(user: User): Promise<ResponseToken> {
    // validate token if token is exist in database but not expired
    const selectToken = await this.prismaService.session_token_user.findUnique({
      where: {
        userId: user.id
      }
    })

    if (selectToken) {
      // verify user token is valid or not from database
      try {
        // verify jwt
        await this.jwtService.verify(selectToken.access_token) // valid or not
        // delete user
        delete user.password
        return {
          user,
          access_token: selectToken.access_token,
          refresh_token: selectToken.refresh_token
        }
      } catch (e) {
        // if error create token
        const { access_token, refresh_token } = await this.generateToken({
          sub: user.id,
          username: user.username
        })
        // TODO: update new token to db
        await this.prismaService.session_token_user.update({
          where: { userId: user.id, access_token: selectToken.access_token },
          data: { access_token }
        })
        delete user.password
        return {
          user,
          access_token,
          refresh_token
        }
      }
    } else {
      // if database session_token is null
      const { access_token, refresh_token } = await this.generateToken({
        sub: user.id,
        username: user.username
      })
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

  protected async generateToken(
    payload: PayloadAccessToken
  ): Promise<Pick<ResponseToken, 'access_token' | 'refresh_token'>> {
    // make payload for encode to jwt
    const payloadToken: PayloadAccessToken = {
      sub: payload.sub,
      username: payload.username
    }
    // make jwt token
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.sign(payloadToken, {
        secret: env.JWT_SECRET
      }),
      this.jwtService.sign(payloadToken, {
        secret: env.JWT_REFRESH_SECRET
      })
    ])
    return {
      access_token,
      refresh_token
    }
  }
}
