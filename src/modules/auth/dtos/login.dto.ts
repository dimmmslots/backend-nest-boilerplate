import { createZodDto } from 'nestjs-zod'
import z from 'zod'

const schema = z.object({
  username: z.string(),
  password: z.string().min(6)
})

export class LoginDTO extends createZodDto(schema) {}
