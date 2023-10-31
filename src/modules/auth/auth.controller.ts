import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common'
import { AuthService } from './auth.service'
import { RegisterUserDTO } from './dtos/register.dto'
import { AuthenticatedGuard } from './guards/auth.guard'
import { LocalAuthGuard } from './guards/local-auth.guard'
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async registerUser(@Body() payload: RegisterUserDTO) {
    await this.authService.registerUser(payload)
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async loginLocal(@Request() req: any) {
    return req.body
  }

  @UseGuards(AuthenticatedGuard)
  @Get('user')
  async user(@Request() req) {
    return req.user
  }

  @UseGuards(AuthenticatedGuard)
  @Post('logout')
  async logout(@Request() req) {
    req.session.destroy()
    return 'ook'
  }
}
