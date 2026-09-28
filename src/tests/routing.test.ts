import { createHash } from 'node:crypto';
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
	// Uploads: o stub conta bytes e tira o hash do corpo cru que chegou.
	for (const type of ['multipart/form-data', 'application/octet-stream']) {
		upvox.addContentTypeParser(type, (_req, payload, done) =>
			done(null, payload),
		);
	}
	upvox.post('/v1/upload', async (req) => {
		const hash = createHash('sha256');
		let bytes = 0;
		for await (const chunk of req.body as AsyncIterable<Buffer>) {
			bytes += chunk.length;
			hash.update(chunk);
		}
		return {
			bytes,
			sha256: hash.digest('hex'),
			contentType: req.headers['content-type'],
			userId: req.headers['x-user-id'] ?? null,
		};
	});
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

	it('multipart passa intacto (boundary, campos e arquivo) com a identidade', async () => {
		const boundary = '----gatewaytest';
		const file = Buffer.alloc(2 * 1024 * 1024, 7);
		const payload = Buffer.concat([
			Buffer.from(
				`--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\nFoto\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`,
			),
			file,
			Buffer.from(`\r\n--${boundary}--\r\n`),
		]);
		const res = await gateway.inject({
			method: 'POST',
			url: '/v1/upload',
			headers: {
				authorization: 'Bearer good',
				'content-type': `multipart/form-data; boundary=${boundary}`,
			},
			payload,
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({
			bytes: payload.length,
			sha256: createHash('sha256').update(payload).digest('hex'),
			contentType: `multipart/form-data; boundary=${boundary}`,
			userId: identity.id,
		});
	});

	it('upload grande (60MB) atravessa o proxy em stream, sem o limite de 1MB', async () => {
		const address = await gateway.listen({ port: 0, host: '127.0.0.1' });
		const big = Buffer.alloc(60 * 1024 * 1024);
		for (let i = 0; i < big.length; i += 4096) big[i] = i % 251;
		// Corpo em pedaços (como vem da rede), não um Buffer só.
		const chunks = (async function* () {
			for (let i = 0; i < big.length; i += 1024 * 1024) {
				yield big.subarray(i, i + 1024 * 1024);
			}
		})();
		const res = await fetch(`${address}/v1/upload`, {
			method: 'POST',
			headers: {
				authorization: 'Bearer good',
				'content-type': 'application/octet-stream',
			},
			body: chunks as never,
			duplex: 'half',
		} as RequestInit);
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({
			bytes: big.length,
			sha256: createHash('sha256').update(big).digest('hex'),
			userId: identity.id,
		});
	}, 30_000);
});
