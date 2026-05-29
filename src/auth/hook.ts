import type { SupabaseClient } from '@supabase/supabase-js';
import type { FastifyRequest } from 'fastify';
import { verifyToken } from '@/auth/verify';

export const USER_HEADERS = [
	'x-user-id',
	'x-user-email',
	'x-user-role',
	'x-user-name',
	'x-user-phone',
	'x-user-blocked',
] as const;

function extractBearer(header: string | undefined): string | null {
	if (!header) return null;
	if (!header.toLowerCase().startsWith('bearer ')) return null;
	const token = header.slice(7).trim();
	return token || null;
}

export function makeAuthHook(supabase: SupabaseClient) {
	return async function authHook(req: FastifyRequest): Promise<void> {
		// Anti-spoofing: never trust client-supplied identity headers.
		for (const h of USER_HEADERS) delete req.headers[h];

		const token = extractBearer(req.headers.authorization);
		if (!token) return;

		const identity = await verifyToken(supabase, token);
		if (!identity) return;

		req.headers['x-user-id'] = identity.id;
		req.headers['x-user-email'] = identity.email;
		req.headers['x-user-role'] = identity.role;
		req.headers['x-user-blocked'] = String(identity.blocked);
		if (identity.name) req.headers['x-user-name'] = identity.name;
		if (identity.phone) req.headers['x-user-phone'] = identity.phone;
	};
}
