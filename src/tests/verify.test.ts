import { describe, expect, it, type Mock, vi } from 'vitest';
import { verifyToken } from '@/auth/verify';

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
