import type { SupabaseClient } from '@supabase/supabase-js';
import { type Identity, IdentitySchema } from '@/auth/schema';

export async function verifyToken(
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
