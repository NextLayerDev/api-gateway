import type { SupabaseClient } from '@supabase/supabase-js';
import { decodeProtectedHeader, jwtVerify } from 'jose';
import { type Identity, IdentitySchema } from '@/auth/schema';

/**
 * Cache por token + dedup in-flight: cada tela dispara várias requests em
 * paralelo (e o chat da live faz polling), e sem isso cada uma pagava
 * `auth.getUser` + SELECT em users. TTL curto para que bloqueio/troca de role
 * propaguem rápido; só cacheia sucesso. Um cache por client (isola testes).
 */
const IDENTITY_TTL_MS = 60_000;
export const MAX_ENTRIES = 5000;

type Entry = { expiresAt: number; identity: Identity };
type TokenCache = {
	store: Map<string, Entry>;
	inflight: Map<string, Promise<Identity | null>>;
};

export type VerifyOptions = {
	/**
	 * `SUPABASE_JWT_SECRET` (HS256). Com ele o token HS256 é conferido aqui,
	 * sem a ida ao auth do Supabase (`getUser`). Token de outro algoritmo
	 * (ES256/RS256, chaves assimétricas) segue pelo `getUser`.
	 */
	jwtSecret?: string;
};

const caches = new WeakMap<SupabaseClient, TokenCache>();
const secretKeys = new Map<string, Uint8Array>();

function cacheFor(supabase: SupabaseClient): TokenCache {
	let cache = caches.get(supabase);
	if (!cache) {
		cache = { store: new Map(), inflight: new Map() };
		caches.set(supabase, cache);
	}
	return cache;
}

function keyFor(secret: string): Uint8Array {
	let key = secretKeys.get(secret);
	if (!key) {
		key = new TextEncoder().encode(secret);
		secretKeys.set(secret, key);
	}
	return key;
}

/** `exp` do JWT em ms (sem verificar assinatura: só encurta o TTL do cache). */
function tokenExpiryMs(token: string): number | null {
	const payload = token.split('.')[1];
	if (!payload) return null;
	try {
		const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
		return typeof exp === 'number' ? exp * 1000 : null;
	} catch {
		return null;
	}
}

function algOf(token: string): string | null {
	try {
		return decodeProtectedHeader(token).alg ?? null;
	} catch {
		return null;
	}
}

/**
 * Id do usuário dono do token. HS256 com o segredo: confere assinatura e
 * validade localmente (assinatura errada ou vencido = null, sem cair no
 * `getUser`). Sem segredo, ou outro algoritmo: pergunta ao auth do Supabase.
 */
async function userIdOf(
	supabase: SupabaseClient,
	token: string,
	opts: VerifyOptions,
): Promise<string | null> {
	if (opts.jwtSecret && algOf(token) === 'HS256') {
		try {
			const { payload } = await jwtVerify(token, keyFor(opts.jwtSecret), {
				algorithms: ['HS256'],
				requiredClaims: ['sub', 'exp'],
			});
			// Chave anon/service (sem usuário) não é identidade.
			return payload.role === 'authenticated' ? (payload.sub ?? null) : null;
		} catch {
			return null;
		}
	}
	const { data, error } = await supabase.auth.getUser(token);
	if (error || !data?.user) return null;
	return data.user.id;
}

async function loadIdentity(
	supabase: SupabaseClient,
	token: string,
	opts: VerifyOptions,
): Promise<Identity | null> {
	const userId = await userIdOf(supabase, token, opts);
	if (!userId) return null;

	const { data: row, error: dbError } = await supabase
		.from('users')
		.select('id, email, role, name, phone, blocked')
		.eq('id', userId)
		.maybeSingle();
	if (dbError || !row) return null;

	const parsed = IdentitySchema.safeParse(row);
	return parsed.success ? parsed.data : null;
}

/**
 * Cheio: sai o usado há mais tempo (o Map guarda a ordem de inserção e um
 * acerto reinsere). Antes o `clear()` derrubava todo mundo de uma vez e o
 * próximo pico refazia milhares de `getUser`.
 */
function remember(store: Map<string, Entry>, token: string, entry: Entry) {
	store.delete(token);
	while (store.size >= MAX_ENTRIES) {
		const oldest = store.keys().next().value;
		if (oldest === undefined) break;
		store.delete(oldest);
	}
	store.set(token, entry);
}

export async function verifyToken(
	supabase: SupabaseClient,
	token: string,
	opts: VerifyOptions = {},
): Promise<Identity | null> {
	const { store, inflight } = cacheFor(supabase);
	const now = Date.now();
	const hit = store.get(token);
	if (hit && hit.expiresAt > now) {
		remember(store, token, hit);
		return hit.identity;
	}
	if (hit) store.delete(token);

	const pending = inflight.get(token);
	if (pending) return pending;

	const p = (async () => {
		try {
			const identity = await loadIdentity(supabase, token, opts);
			if (identity) {
				const expiresAt = Math.min(
					Date.now() + IDENTITY_TTL_MS,
					tokenExpiryMs(token) ?? Number.POSITIVE_INFINITY,
				);
				remember(store, token, { expiresAt, identity });
			}
			return identity;
		} finally {
			inflight.delete(token);
		}
	})();
	inflight.set(token, p);
	return p;
}
