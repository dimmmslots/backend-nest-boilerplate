import { JwtAuthGuard } from '@/modules/auth/guards/jwt-auth.guard'
import { LocalAuthGuard } from '@/modules/auth/guards/local-auth.guard'
import { Body, Controller, Get, Post, Request, UseGuards, HttpCode, HttpStatus } from '@nestjs/common'
import { AuthService } from './auth.service'
import { RegisterUserDTO } from './dtos/register.dto'

/**
 * guards explain :
 * if you use passport-local
 * you can use class AuthenticatedGuard import from @/modules/auth/guards/auth.guard
 * if you use passport-jwt
 * you can use class JwtAuthGuard import from @/modules/auth/guards/jwt-auth.guard
 *
 * note :
 * LocalAuthGuard import from @/modules/auth/guards/local-auth.guard used for validate login passport
 */
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async registerUser(@Body() payload: RegisterUserDTO) {
    return await this.authService.registerUser(payload)
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  /**
   * default login is local
   * but if call authService with method loginJwt(req.user)
   * can change strategy login with jwt
   * Local Strategy (default) :
   * - req.user -> @returns User
   * JWT Strategy :
   * - this.authService.loginJwt(req.user) -> @returns ResponseToken
   */
  async login(@Request() req: any) {
    return await this.authService.loginJwt(req.user)
  }

  @UseGuards(JwtAuthGuard)
  @Get('user')
  async user(@Request() req) {
    return req.user
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  /**
   * if you use passport-local
   * use function logout(req)
   * if you use passport-jwt
   * use function logoutJwt(req)
   */
  async logout(@Request() req) {
    return await this.authService.logoutJwt(req)
  }
}
