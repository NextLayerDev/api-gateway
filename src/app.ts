import httpProxy from '@fastify/http-proxy';
import { createClient } from '@supabase/supabase-js';
import Fastify, { type FastifyInstance } from 'fastify';
import { makeAuthHook } from '@/auth/hook';
import { env } from '@/config/env';

export function buildApp(): FastifyInstance {
	const app = Fastify({ logger: true });

	const supabase = createClient(
		env.SUPABASE_URL,
		env.SUPABASE_SERVICE_ROLE_KEY,
		{ auth: { persistSession: false, autoRefreshToken: false } },
	);

	// Validate token + inject trusted identity headers on every request.
	app.addHook('onRequest', makeAuthHook(supabase));

	// Gateway-owned healthcheck (static route wins over the catch-all proxy).
	app.get('/healthz', async () => ({ status: 'ok' }));

	// Specific prefix first: /v1/* -> upvox-api (no rewrite).
	app.register(httpProxy, {
		upstream: env.UPVOX_UPSTREAM,
		prefix: '/v1',
		rewritePrefix: '/v1',
	});

	// Catch-all: everything else -> laser-api (root paths, no rewrite).
	app.register(httpProxy, {
		upstream: env.LASER_UPSTREAM,
		prefix: '/',
	});

	return app;
}
