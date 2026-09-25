import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const identity = {
	id: '11111111-1111-4111-8111-111111111111',
	email: 'a@b.com',
	role: 'staff' as const,
	name: null,
	phone: null,
	blocked: false,
};

// Stub the token verification so we do not call Supabase.
vi.mock('@/auth/verify', () => ({
	verifyToken: vi.fn(async (_s: unknown, token: string) =>
		token === 'good' ? identity : null,
	),
}));

// Build two stub upstreams that echo what they received, then point env at them.
let upvox: FastifyInstance;
let laser: FastifyInstance;
let gateway: FastifyInstance;

beforeAll(async () => {
	upvox = Fastify();
	upvox.all('/*', async (req) => ({
		who: 'upvox',
		url: req.url,
		userId: req.headers['x-user-id'] ?? null,
		secret: req.headers['x-gateway-secret'] ?? null,
		body: req.body ?? null,
	}));
	const upvoxAddr = await upvox.listen({ port: 0, host: '127.0.0.1' });

	laser = Fastify();
	laser.addContentTypeParser(
		'application/json',
		{ parseAs: 'buffer' },
		(_req, body, done) => done(null, body),
	);
	laser.all('/*', async (req) => ({
		who: 'laser',
		url: req.url,
		userId: req.headers['x-user-id'] ?? null,
		rawBody: (req.body as Buffer | undefined)?.toString() ?? null,
	}));
	const laserAddr = await laser.listen({ port: 0, host: '127.0.0.1' });

	process.env.SUPABASE_URL = 'https://example.supabase.co';
	process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-key';
	process.env.UPVOX_UPSTREAM = upvoxAddr;
	process.env.LASER_UPSTREAM = laserAddr;
	process.env.GATEWAY_SHARED_SECRET = 'gateway-secret-0123456789';
	process.env.CORS_ORIGINS =
		'https://app.example.com, https://admin.example.com/';

	const { buildApp } = await import('@/app');
	gateway = buildApp();
	await gateway.ready();
});

afterAll(async () => {
	await gateway.close();
	await upvox.close();
	await laser.close();
});

describe('gateway routing', () => {
	it('routes /v1/* to the upvox upstream', async () => {
		const res = await gateway.inject({ method: 'GET', url: '/v1/courses' });
		expect(res.json()).toMatchObject({ who: 'upvox', url: '/v1/courses' });
	});

	it('routes everything else to the laser upstream', async () => {
		const res = await gateway.inject({ method: 'GET', url: '/course/abc' });
		expect(res.json()).toMatchObject({ who: 'laser', url: '/course/abc' });
	});

	it('answers /healthz itself, not the catch-all', async () => {
		const res = await gateway.inject({ method: 'GET', url: '/healthz' });
		expect(res.json()).toEqual({ status: 'ok' });
	});

	it('forwards injected identity to the upstream for a valid token', async () => {
		const res = await gateway.inject({
			method: 'GET',
			url: '/course/abc',
			headers: { authorization: 'Bearer good' },
		});
		expect(res.json().userId).toBe(identity.id);
	});

	it('sends the shared secret to the upvox upstream', async () => {
		const res = await gateway.inject({
			method: 'GET',
			url: '/v1/courses',
			headers: { 'x-gateway-secret': 'forged' },
		});
		expect(res.json().secret).toBe('gateway-secret-0123456789');
	});

	it('answers the preflight itself, without reaching the upstream', async () => {
		const res = await gateway.inject({
			method: 'OPTIONS',
			url: '/v1/courses',
			headers: { origin: 'https://app.example.com' },
		});
		expect(res.statusCode).toBe(204);
		expect(res.body).toBe('');
		expect(res.headers['access-control-allow-origin']).toBe(
			'https://app.example.com',
		);
	});

	it('does not grant CORS to an origin outside CORS_ORIGINS', async () => {
		const res = await gateway.inject({
			method: 'GET',
			url: '/v1/courses',
			headers: { origin: 'https://evil.example.com' },
		});
		expect(res.headers['access-control-allow-origin']).toBeUndefined();
		expect(res.headers['access-control-allow-credentials']).toBeUndefined();
	});

	it('normalizes a trailing slash in CORS_ORIGINS', async () => {
		const res = await gateway.inject({
			method: 'GET',
			url: '/v1/courses',
			headers: { origin: 'https://admin.example.com' },
		});
		expect(res.headers['access-control-allow-origin']).toBe(
			'https://admin.example.com',
		);
	});

	it('forwards a raw JSON body intact (Stripe webhook safety)', async () => {
		const payload = JSON.stringify({ type: 'evt', id: 'x' });
		const res = await gateway.inject({
			method: 'POST',
			url: '/webhook/stripe',
			headers: { 'content-type': 'application/json' },
			payload,
		});
		expect(res.json().rawBody).toBe(payload);
	});
});
