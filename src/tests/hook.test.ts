import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { makeAuthHook } from '@/auth/hook';

const identity = {
	id: '11111111-1111-4111-8111-111111111111',
	email: 'a@b.com',
	role: 'admin' as const,
	name: 'Tobias',
	phone: null,
	blocked: false,
};

vi.mock('@/auth/verify', () => ({
	verifyToken: vi.fn(async (_s: unknown, token: string) =>
		token === 'good' ? identity : null,
	),
}));

function req(headers: Record<string, string>): FastifyRequest {
	return { headers } as unknown as FastifyRequest;
}

describe('makeAuthHook', () => {
	const hook = makeAuthHook({} as never);

	it('strips client-supplied x-user-* headers before validating', async () => {
		const r = req({ 'x-user-id': 'forged', 'x-user-role': 'admin' });
		await hook(r);
		expect(r.headers['x-user-id']).toBeUndefined();
		expect(r.headers['x-user-role']).toBeUndefined();
	});

	it('injects identity headers for a valid token', async () => {
		const r = req({ authorization: 'Bearer good' });
		await hook(r);
		expect(r.headers['x-user-id']).toBe(identity.id);
		expect(r.headers['x-user-email']).toBe(identity.email);
		expect(r.headers['x-user-role']).toBe('admin');
		expect(r.headers['x-user-name']).toBe('Tobias');
		expect(r.headers['x-user-blocked']).toBe('false');
		expect(r.headers['x-user-phone']).toBeUndefined();
	});

	it('overwrites a forged header even with a valid token', async () => {
		const r = req({ authorization: 'Bearer good', 'x-user-role': 'admin' });
		await hook(r);
		expect(r.headers['x-user-role']).toBe('admin');
		expect(r.headers['x-user-id']).toBe(identity.id);
	});

	it('injects nothing when there is no token', async () => {
		const r = req({});
		await hook(r);
		expect(r.headers['x-user-id']).toBeUndefined();
	});

	it('injects nothing when the token is invalid', async () => {
		const r = req({ authorization: 'Bearer bad' });
		await hook(r);
		expect(r.headers['x-user-id']).toBeUndefined();
	});
});
