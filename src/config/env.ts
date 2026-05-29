import { z } from 'zod';

const EnvSchema = z.object({
	PORT: z.coerce.number().int().positive().default(8080),
	SUPABASE_URL: z.url(),
	SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
	UPVOX_UPSTREAM: z.url(),
	LASER_UPSTREAM: z.url(),
});

export type Env = z.infer<typeof EnvSchema>;

export const env: Env = EnvSchema.parse(process.env);
