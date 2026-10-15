const { createClient } = require('@supabase/supabase-js');

// This client is server-only. Never attach Discord OAuth tokens to it.
function createAuthUsersStore({ env = process.env, fetch: fetchImpl, timeoutMs = 10000 } = {}) {
    let client;

    function getClient() {
        if (client) return client;
        const url = env.SUPABASE_URL;
        const key = env.SUPABASE_SECRET_KEY;
        try {
            const parsed = new URL(url);
            if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !key?.trim()) {
                throw new Error();
            }
            client = createClient(url, key, {
                auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
                ...(fetchImpl ? { global: { fetch: fetchImpl } } : {})
            });
        } catch {
            throw new Error('SUPABASE_CONFIGURATION_INVALID');
        }
        return client;
    }

    return {
        async saveVerifiedUser(user, verifiedAt) {
            // Explicit allowlist: callers may carry private fields from the legacy store.
            const row = {
                discord_id: user.id,
                username: user.username,
                avatar: user.avatar ?? null,
                verified_at: verifiedAt,
                updated_at: verifiedAt
            };
            if (typeof row.discord_id !== 'string' || !/^\d{17,20}$/.test(row.discord_id) ||
                typeof row.username !== 'string' || !row.username ||
                (row.avatar !== null && typeof row.avatar !== 'string') ||
                typeof verifiedAt !== 'string' || !Number.isFinite(Date.parse(verifiedAt))) {
                throw new Error('VERIFIED_USER_INVALID');
            }
            const db = getClient();
            try {
                const { data, error } = await db.schema('public').from('auth_users')
                    .upsert(row, { onConflict: 'discord_id' })
                    .select('discord_id')
                    .single()
                    .retry(false)
                    .abortSignal(AbortSignal.timeout(timeoutMs));
                if (error || data?.discord_id !== row.discord_id) throw new Error();
            } catch {
                // Do not propagate provider messages, response bodies or credentials.
                throw new Error('AUTH_USERS_SAVE_FAILED');
            }
        }
    };
}

module.exports = { createAuthUsersStore };
