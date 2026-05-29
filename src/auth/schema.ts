import { z } from 'zod';

export const RoleSchema = z.enum(['customer', 'staff', 'admin']);
export type Role = z.infer<typeof RoleSchema>;

export const IdentitySchema = z.object({
	id: z.uuid(),
	email: z.email(),
	role: RoleSchema,
	name: z.string().nullable(),
	phone: z.string().nullable(),
	blocked: z.boolean(),
});

export type Identity = z.infer<typeof IdentitySchema>;
