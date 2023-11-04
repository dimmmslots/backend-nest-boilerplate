import { Injectable, Inject, forwardRef } from '@nestjs/common'
import { Request } from 'express'
import { JwtService } from '@nestjs/jwt'
import { PayloadToken } from '@/types/jwt'
import { env } from 'process'

@Injectable()
export class JwtUtilService {
  constructor(private readonly jwtService: JwtService) {}

  /**
   * Extract token from header
   * @param request
   * @returns string
   */
  extractToken(request: Request): string | undefined {
    const authorizationHeader = request.headers.authorization
    if (!authorizationHeader) return undefined
    const [type, token] = authorizationHeader.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }

  async generateAccessToken(payload: PayloadToken) {
    return await this.jwtService.signAsync(payload, {
      secret: env.JWT_SECRET,
      expiresIn: '50s'
    })
  }

  async generateRefreshToken(payload: PayloadToken) {
    return await this.jwtService.signAsync(payload, {
      secret: env.JWT_REFRESH_SECRET,
      expiresIn: '1m'
    })
  }
}
