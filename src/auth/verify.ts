import type { SupabaseClient } from '@supabase/supabase-js';
import { type Identity, IdentitySchema } from '@/auth/schema';

/**
 * Cache por token + dedup in-flight: cada tela dispara várias requests em
 * paralelo (e o chat da live faz polling), e sem isso cada uma pagava
 * `auth.getUser` + SELECT em users. TTL curto para que bloqueio/troca de role
 * propaguem rápido; só cacheia sucesso. Um cache por client (isola testes).
 */
const IDENTITY_TTL_MS = 60_000;
const MAX_ENTRIES = 5000;

type Entry = { expiresAt: number; identity: Identity };
type TokenCache = {
	store: Map<string, Entry>;
	inflight: Map<string, Promise<Identity | null>>;
};

const caches = new WeakMap<SupabaseClient, TokenCache>();

function cacheFor(supabase: SupabaseClient): TokenCache {
	let cache = caches.get(supabase);
	if (!cache) {
		cache = { store: new Map(), inflight: new Map() };
		caches.set(supabase, cache);
	}
	return cache;
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

async function loadIdentity(
	supabase: SupabaseClient,
	token: string,
): Promise<Identity | null> {
	const { data, error } = await supabase.auth.getUser(token);
	if (error || !data?.user) return null;

	const { data: row, error: dbError } = await supabase
		.from('users')
		.select('id, email, role, name, phone, blocked')
		.eq('id', data.user.id)
		.maybeSingle();
	if (dbError || !row) return null;

	const parsed = IdentitySchema.safeParse(row);
	return parsed.success ? parsed.data : null;
}

export async function verifyToken(
	supabase: SupabaseClient,
	token: string,
): Promise<Identity | null> {
	const { store, inflight } = cacheFor(supabase);
	const now = Date.now();
	const hit = store.get(token);
	if (hit && hit.expiresAt > now) return hit.identity;
	if (hit) store.delete(token);

	const pending = inflight.get(token);
	if (pending) return pending;

	const p = (async () => {
		try {
			const identity = await loadIdentity(supabase, token);
			if (identity) {
				const expiresAt = Math.min(
					Date.now() + IDENTITY_TTL_MS,
					tokenExpiryMs(token) ?? Number.POSITIVE_INFINITY,
				);
				if (store.size >= MAX_ENTRIES) store.clear();
				store.set(token, { expiresAt, identity });
			}
			return identity;
		} finally {
			inflight.delete(token);
		}
	})();
	inflight.set(token, p);
	return p;
}
