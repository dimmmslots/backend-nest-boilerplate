import { Body, Controller, Get, Post } from '@nestjs/common'
import { UserService } from './user.service'

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  async GetAllUsers() {
    return await this.userService.getAllUsers()
  }
}
