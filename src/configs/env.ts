import z from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string(),
  PORT: z.string().optional(),
  JWT_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string()
})

export default envSchema.parse(process.env)
