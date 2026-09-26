import { SignJWT } from 'jose';
import { describe, expect, it, type Mock, vi } from 'vitest';
import { MAX_ENTRIES, verifyToken } from '@/auth/verify';

const row = {
	id: '11111111-1111-4111-8111-111111111111',
	email: 'a@b.com',
	role: 'customer',
	name: null,
	phone: null,
	blocked: false,
};

function fakeSupabase(opts: {
	authUser: { id: string } | null;
	dbRow: typeof row | null;
}) {
	return {
		auth: {
			getUser: vi.fn().mockResolvedValue({
				data: { user: opts.authUser },
				error: opts.authUser ? null : { message: 'invalid' },
			}),
		},
		from: vi.fn().mockReturnValue({
			select: vi.fn().mockReturnThis(),
			eq: vi.fn().mockReturnThis(),
			maybeSingle: vi.fn().mockResolvedValue({ data: opts.dbRow, error: null }),
		}),
	} as never;
}

describe('verifyToken', () => {
	it('returns the identity for a valid token with a users row', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const identity = await verifyToken(supabase, 'good-token');
		expect(identity).toMatchObject({ id: row.id, role: 'customer' });
	});

	it('returns null when the token is invalid', async () => {
		const supabase = fakeSupabase({ authUser: null, dbRow: null });
		expect(await verifyToken(supabase, 'bad-token')).toBeNull();
	});

	it('returns null when the users row is missing', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: null });
		expect(await verifyToken(supabase, 'good-token')).toBeNull();
	});

	it('reuses the identity for the same token (cache + dedup)', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const getUser = (supabase as unknown as { auth: { getUser: Mock } }).auth
			.getUser;
		await Promise.all([
			verifyToken(supabase, 'tok'),
			verifyToken(supabase, 'tok'),
		]);
		await verifyToken(supabase, 'tok');
		expect(getUser).toHaveBeenCalledTimes(1);
	});

	it('does not cache a failed validation', async () => {
		const supabase = fakeSupabase({ authUser: null, dbRow: null });
		const getUser = (supabase as unknown as { auth: { getUser: Mock } }).auth
			.getUser;
		await verifyToken(supabase, 'bad-token');
		await verifyToken(supabase, 'bad-token');
		expect(getUser).toHaveBeenCalledTimes(2);
	});

	it('does not serve a cached identity past the JWT exp', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const getUser = (supabase as unknown as { auth: { getUser: Mock } }).auth
			.getUser;
		const exp = Math.floor(Date.now() / 1000) - 1;
		const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
		const token = `h.${payload}.s`;
		await verifyToken(supabase, token);
		await verifyToken(supabase, token);
		expect(getUser).toHaveBeenCalledTimes(2);
	});
});

const SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';
const key = new TextEncoder().encode(SECRET);
const getUserOf = (s: unknown) =>
	(s as { auth: { getUser: Mock } }).auth.getUser;

function hs256(
	claims: Record<string, unknown>,
	opts: { secret?: Uint8Array; expSeconds?: number } = {},
) {
	return new SignJWT({ role: 'authenticated', ...claims })
		.setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
		.setSubject(row.id)
		.setExpirationTime(
			Math.floor(Date.now() / 1000) + (opts.expSeconds ?? 3600),
		)
		.sign(opts.secret ?? key);
}

describe('verifyToken — JWT local (SUPABASE_JWT_SECRET)', () => {
	it('HS256 válido: identidade sem chamar o auth do Supabase', async () => {
		const supabase = fakeSupabase({ authUser: null, dbRow: row });
		const identity = await verifyToken(supabase, await hs256({}), {
			jwtSecret: SECRET,
		});
		expect(identity).toMatchObject({ id: row.id, role: 'customer' });
		expect(getUserOf(supabase)).not.toHaveBeenCalled();
	});

	it('assinatura com outro segredo: null, sem cair no getUser', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const forged = await hs256(
			{},
			{ secret: new TextEncoder().encode('x'.repeat(40)) },
		);
		expect(await verifyToken(supabase, forged, { jwtSecret: SECRET })).toBe(
			null,
		);
		expect(getUserOf(supabase)).not.toHaveBeenCalled();
	});

	it('vencido: null', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const expired = await hs256({}, { expSeconds: -60 });
		expect(await verifyToken(supabase, expired, { jwtSecret: SECRET })).toBe(
			null,
		);
	});

	it('chave anon/service (sem usuário) não vira identidade', async () => {
		const supabase = fakeSupabase({ authUser: null, dbRow: row });
		const anon = await hs256({ role: 'anon' });
		expect(await verifyToken(supabase, anon, { jwtSecret: SECRET })).toBe(null);
	});

	it('token assimétrico (ES256) com o segredo configurado segue pelo getUser', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const header = Buffer.from(
			JSON.stringify({ alg: 'ES256', typ: 'JWT' }),
		).toString('base64url');
		const body = Buffer.from(JSON.stringify({ sub: row.id })).toString(
			'base64url',
		);
		const identity = await verifyToken(supabase, `${header}.${body}.sig`, {
			jwtSecret: SECRET,
		});
		expect(identity).toMatchObject({ id: row.id });
		expect(getUserOf(supabase)).toHaveBeenCalledTimes(1);
	});

	it('sem o segredo: HS256 também vai ao getUser (comportamento antigo)', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		await verifyToken(supabase, await hs256({}));
		expect(getUserOf(supabase)).toHaveBeenCalledTimes(1);
	});
});

describe('verifyToken — cache LRU', () => {
	it('cheio: sai só o menos usado (antes o cache inteiro era apagado)', async () => {
		const supabase = fakeSupabase({ authUser: { id: row.id }, dbRow: row });
		const getUser = getUserOf(supabase);
		for (let i = 0; i < MAX_ENTRIES; i++) await verifyToken(supabase, `t${i}`);
		// t0 usado de novo: vira o mais recente; o menos usado passa a ser t1.
		await verifyToken(supabase, 't0');
		await verifyToken(supabase, 'novo');
		getUser.mockClear();
		await verifyToken(supabase, 't0');
		await verifyToken(supabase, `t${MAX_ENTRIES - 1}`);
		expect(getUser).not.toHaveBeenCalled();
		await verifyToken(supabase, 't1');
		expect(getUser).toHaveBeenCalledTimes(1);
	});
});
