import { z } from 'zod';

const EnvSchema = z.object({
	PORT: z.coerce.number().int().positive().default(8080),
	SUPABASE_URL: z.url(),
	SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
	UPVOX_UPSTREAM: z.url(),
	LASER_UPSTREAM: z.url(),
	// Segredo compartilhado com a upvox-api: vai no header `x-gateway-secret`
	// e é o que faz a API confiar nos `x-user-*` injetados aqui.
	GATEWAY_SHARED_SECRET: z.preprocess(
		(v) => (v === '' ? undefined : v),
		z.string().min(16).optional(),
	),
	// Segredo JWT do projeto (Settings › API › JWT secret). Opcional: com ele
	// o token HS256 é verificado aqui com jose, sem chamar o auth do Supabase.
	SUPABASE_JWT_SECRET: z.preprocess(
		(v) => (v === '' ? undefined : v),
		z.string().min(32).optional(),
	),
	// Origens liberadas no CORS, separadas por vírgula. Vazio = reflete
	// qualquer origem (comportamento antigo) — configure em produção.
	CORS_ORIGINS: z.preprocess(
		(v) => (v === '' ? undefined : v),
		z
			.string()
			.optional()
			.transform((v) =>
				v
					? v
							.split(',')
							.map((o) => o.trim().replace(/\/$/, ''))
							.filter(Boolean)
					: [],
			),
	),
});

export type Env = z.infer<typeof EnvSchema>;

export const env: Env = EnvSchema.parse(process.env);
