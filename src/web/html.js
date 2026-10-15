const fs = require('node:fs');

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function safeUrl(value, kind) {
    try {
        const url = new URL(value);
        if (url.protocol !== 'https:' || url.username || url.password || url.port) return '';
        if (kind === 'guildUrl') return url.hostname === 'discord.com' && /^\/channels\/\d+$/.test(url.pathname) && !url.search && !url.hash ? url.href : '';
        return url.hostname === 'cdn.discordapp.com' ? url.href : '';
    } catch { return ''; }
}

// Templates use these substitutions only in text or quoted HTML attributes, never JS/CSS.
function renderHtml(template, options) {
    return template.replace(/<%=\s*(\w+)\s*%>/g, (_match, key) => {
        const value = Object.hasOwn(options, key) ? options[key] : '';
        if (typeof value !== 'string' && typeof value !== 'number') return '';
        return escapeHtml(['userAvatar', 'guildIcon', 'guildUrl'].includes(key) ? safeUrl(value, key) : value);
    });
}

function htmlEngine(filePath, options, callback) {
    fs.readFile(filePath, 'utf8', (error, template) => {
        if (error) return callback(error);
        try { callback(null, renderHtml(template, options)); } catch (error) { callback(error); }
    });
}

module.exports = { escapeHtml, renderHtml, htmlEngine };
