import { describe, expect, it, vi } from 'vitest';
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
});
