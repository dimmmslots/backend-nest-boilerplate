import { createZodDto } from 'nestjs-zod'
import z from 'zod'

const schema = z.object({
  username: z.string().min(6),
  email: z.string().email(),
  password: z.string().min(6)
})

export class RegisterUserDTO extends createZodDto(schema) {}
