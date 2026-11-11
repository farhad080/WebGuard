function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  get jwtSecret(): string {
    return required('JWT_SECRET');
  },
  jwtExpiresIn: '1h',
} as const;
