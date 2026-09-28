import type { SupabaseClient } from '@supabase/supabase-js';
import type { FastifyRequest } from 'fastify';
import { type VerifyOptions, verifyToken } from '@/auth/verify';

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

// Mesmo critério do Node http/undici: fora disso o proxy lança "Invalid
// character in header" e toda request do usuário vira 500.
const INVALID_HEADER_CHAR = /[^\t\x20-\x7e\x80-\xff]/;

function safeHeaderValue(value: string | null): string | null {
	return value && !INVALID_HEADER_CHAR.test(value) ? value : null;
}

/** Header que prova para os upstreams que a identidade foi injetada aqui. */
export const GATEWAY_SECRET_HEADER = 'x-gateway-secret';

export function makeAuthHook(
	supabase: SupabaseClient,
	gatewaySecret?: string,
	opts: VerifyOptions = {},
) {
	return async function authHook(req: FastifyRequest): Promise<void> {
		// Anti-spoofing: never trust client-supplied identity headers.
		for (const h of USER_HEADERS) delete req.headers[h];
		delete req.headers[GATEWAY_SECRET_HEADER];
		if (gatewaySecret) req.headers[GATEWAY_SECRET_HEADER] = gatewaySecret;

		const token = extractBearer(req.headers.authorization);
		if (!token) return;

		const identity = await verifyToken(supabase, token, opts);
		if (!identity) return;

		req.headers['x-user-id'] = identity.id;
		req.headers['x-user-email'] = identity.email;
		req.headers['x-user-role'] = identity.role;
		req.headers['x-user-blocked'] = String(identity.blocked);
		// name/phone são informativos (a laser-api cai em null sem eles): um
		// nome com emoji ou ’ não pode derrubar as requests do usuário.
		const name = safeHeaderValue(identity.name);
		const phone = safeHeaderValue(identity.phone);
		if (name) req.headers['x-user-name'] = name;
		if (phone) req.headers['x-user-phone'] = phone;
	};
}
