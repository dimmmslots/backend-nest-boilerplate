import { Injectable } from '@nestjs/common'
import { PrismaService } from '@db/prisma.service'

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async getAllUsers() {
    return await this.prismaService.user.findMany()
  }

  async findUserSession(id: string, access_token: string) {
    return await this.prismaService.session_token_user.findUnique({
      where: { userId: id, access_token }
    })
  }
}
