const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

test('importing legacy stores performs no JSON IO; first legacy access preserves paths and receiver', () => {
    const created = [];
    class JsonDatabase {
        constructor(options) { this.options = options; this.records = {}; created.push(this); }
        set(key, value) { this.records[key] = value; }
        get(key) { return this.records[key]; }
    }
    const filename = path.resolve(__dirname, '../src/database/index.js');
    const context = { module: { exports: {} }, __dirname: path.dirname(filename),
        require: name => name === 'wio.db' ? { JsonDatabase } : require(name) };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context);
    const { users, config, message } = context.module.exports;
    assert.equal(created.length, 0);
    users.set('synthetic', 'value');
    assert.equal(users.get('synthetic'), 'value');
    assert.equal(created.length, 1);
    assert.equal(created[0].options.databasePath, path.resolve(__dirname, '../src/DataBaseJson/users.json'));
    config.get('roleId'); message.get('content');
    assert.equal(created.length, 3);
});
