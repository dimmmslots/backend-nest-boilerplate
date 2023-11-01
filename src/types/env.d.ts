declare global {
  namespace NodeJS {
    interface ProcessEnv {
      DATABASE_URL: 'postgresql://johndoe:password@host:port/dbname?schema=public'
      PORT?: number
      JWT_SECRET: string
      JWT_REFRESH_SECRET: string
    }
  }
}

export {}
