import { Injectable } from '@nestjs/common'
import { PrismaService } from '@prisma/prisma.service'

@Injectable()
export class UserService {
  constructor(private readonly prismaService: PrismaService) {}

  async getAllUsers() {
    return await this.prismaService.user.findMany()
  }

  async findUnique({ username, id }: { username: string; id: string }) {
    return await this.prismaService.user.findUnique({
      where: {
        id,
        username
      },
      include: {
        session_token_user: true
      }
    })
  }
}
