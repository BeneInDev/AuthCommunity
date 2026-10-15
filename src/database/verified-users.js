const { createAuthUsersStore } = require('./supabase');

// Compatibility boundary: commands still read wio.db until their separate migration.
function createVerifiedUsersRepository({ legacyUsers, persistentUsers = createAuthUsersStore() }) {
    return {
        async saveVerification(record) {
            // A failed persistent write must not create a locally verified user.
            await persistentUsers.saveVerifiedUser(record, record.verifiedAt);
            // Preserve the existing JSON format and OAuth credentials for existing commands.
            try {
                await legacyUsers.set(record.id, record);
            } catch {
                // Remote data is retained: never compensate by deleting a verified user.
                throw new Error('LEGACY_USERS_SAVE_FAILED');
            }
        }
    };
}

module.exports = { createVerifiedUsersRepository };
