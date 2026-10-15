const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const discord = require('discord.js');

// Load the unchanged command flow with an in-memory database; never initialize wio.db.
function loadHandler(database, http, logs, { env = {}, privateMembers } = {}) {
    const filename = path.join(__dirname, '../src/commands/handler.js');
    const sandbox = {
        module: { exports: {} }, process: { env: { TOKEN: 'test-bot-placeholder', ...env } },
        console: { error: (...args) => logs.push(args) },
        require: name => {
            if (name === 'discord.js') return discord;
            if (name === '../database') return database;
            if (name === 'axios') return http;
            if (name === '../security/authorization') {
                const auth = require('../src/security/authorization');
                return { ...auth, requireOwner: interaction => auth.requireOwner(interaction, 'owner') };
            }
            if (name === '../http-options') return require('../src/http-options');
            if (name === '../web/oauth-state') return require('../src/web/oauth-state');
            if (name === '../security/private-members' && privateMembers) return privateMembers;
            throw new Error('Unexpected dependency');
        }
    };
    vm.runInNewContext(fs.readFileSync(filename, 'utf8'), sandbox, { filename });
    return sandbox.module.exports;
}

test('member command preserves requests and counters while sanitizing all failure logs', async () => {
    const privateData = { access_token: 'private-access', refresh_token: 'private-refresh', email: 'private@example.invalid', ip: '192.0.2.1' };
    const records = [
        { ...privateData, id: '0' },
        ...['1', '2', '3', '4'].map(id => ({ ...privateData, id }))
    ];
    const logs = [];
    const requests = [];
    const replies = [];
    const handler = loadHandler({ users: { all: () => records } }, {
        put: async (url, body, options) => {
            assert.equal(options.timeout, 10000);
            assert.equal(options.maxRedirects, 0);
            requests.push(url);
            assert.equal(body.access_token, privateData.access_token);
            if (url.endsWith('/1')) return { status: 201 };
            if (url.endsWith('/2')) return { status: 204 };
            if (url.endsWith('/3')) return { status: 403, data: privateData };
            throw new Error(JSON.stringify(privateData));
        }
    }, logs);
    await handler.handleInteraction({
        user: { id: 'owner' },
        isButton: () => false, isModalSubmit: () => true, customId: 'puxar_modal',
        fields: { getTextInputValue: key => key === 'amount' ? '5' : 'test-target' },
        reply: async message => replies.push(message), editReply: async message => replies.push(message)
    }, {});
    assert.equal(requests.length, 4);
    assert.equal(requests.every(url => url.includes('/guilds/test-target/members/')), true);
    const final = replies.at(-1).content;
    assert.match(final, /Membros puxados: 1/);
    assert.match(final, /Já estavam no servidor: 1/);
    assert.match(final, /Falhas: 3/);
    assert.equal(logs.length, 3);
    for (const secret of Object.values(privateData)) {
        assert.equal(JSON.stringify({ logs, replies }).includes(secret), false);
    }
});

for (const customId of ['config_role', 'config_logs', 'config_puxar', 'modal_role', 'modal_logs', 'puxar_modal']) {
    test(`handler blocks non-owner for ${customId} before database or HTTP access`, async () => {
        const replies = [];
        const handler = loadHandler({}, { put: () => assert.fail('Unexpected HTTP') }, []);
        await handler.handleInteraction({ customId, user: { id: 'stranger' }, reply: async message => replies.push(message) }, {});
        assert.equal(replies.length, 1);
        assert.equal(replies[0].flags, discord.MessageFlags.Ephemeral);
    });
}

test('public verification button remains available to a non-owner', async t => {
    const previous = process.env.REDIRECT_URI;
    process.env.REDIRECT_URI = 'https://example.test/oauth2/callback';
    t.after(() => { if (previous === undefined) delete process.env.REDIRECT_URI; else process.env.REDIRECT_URI = previous; });
    const replies = [];
    const handler = loadHandler({}, {}, []);
    await handler.handleInteraction({ user: { id: 'visitor' }, customId: 'verify_button', isButton: () => true,
        reply: async message => replies.push(message) }, {});
    const button = replies[0].components[0].toJSON().components[0];
    assert.equal(button.url, 'https://example.test/oauth2/start');
});

test('interaction errors cannot escape as raw exceptions in logs', async t => {
    const event = require('../src/events/interactionCreate');
    const logs = [];
    t.mock.method(console, 'error', (...args) => logs.push(args));
    await event.execute({ isChatInputCommand: () => false, isButton: () => true }, {
        commands: new Map([['handler', { handleInteraction: async () => { throw new Error('private-access'); } }]])
    });
    assert.deepEqual(logs, [['INTERACTION_FAILED']]);
});

test('private /puxar never reads JSON, including service failures', async () => {
    for(const fails of [false,true]) {
        const replies=[];let runs=0;
        const handler=loadHandler({users:{all:()=>assert.fail('JSON accessed')}},{put:()=>assert.fail('legacy HTTP')},[],{
            env:{OAUTH_MEMBER_JOIN_ENABLED:'true'},privateMembers:{enabled:()=>true,get:()=>({run:async args=>{
                runs++;assert.equal(args.amount,2);assert.equal(args.guildId,'9000000000000000002');
                if(fails)throw new Error('sensitive-provider-data');
                return{joined:1,already_member:0,pending:1,failed:0,uncertain:0,skipped:0,stopped:false};
            }})}});
        await handler.handleInteraction({user:{id:'owner'},customId:'puxar_modal',isButton:()=>false,isModalSubmit:()=>true,
            fields:{getTextInputValue:key=>key==='amount'?'2':'9000000000000000002'},
            deferReply:async()=>{},editReply:async reply=>replies.push(reply)},{});
        assert.equal(runs,1);assert.equal(JSON.stringify(replies).includes('sensitive-provider-data'),false);
        assert.match(replies[0].content,fails ? /Não foi possível/ : /Incluídos: 1/);
    }
});

test('private /puxar rejects malformed amount before service access',async()=>{
    const handler=loadHandler({users:{all:()=>assert.fail('JSON accessed')}},{},[],{
        env:{OAUTH_MEMBER_JOIN_ENABLED:'true'},privateMembers:{enabled:()=>true,get:()=>assert.fail('service invoked')}});
    const replies=[];
    await handler.handleInteraction({user:{id:'owner'},customId:'puxar_modal',isButton:()=>false,isModalSubmit:()=>true,
        fields:{getTextInputValue:()=>'-1'},deferReply:async()=>{},editReply:async reply=>replies.push(reply)},{});
    assert.match(replies[0].content,/Não foi possível/);
});

test('private slash modal avoids legacy count and requires the private configuration',async()=>{
    const filename=path.join(__dirname,'../src/commands/puxar.js');let checked=0,modal;
    const sandbox={module:{exports:{}},process:{env:{OAUTH_MEMBER_JOIN_ENABLED:'true'}},require:name=>{
        if(name==='discord.js')return discord;
        if(name==='../database')return{users:{all:()=>assert.fail('JSON accessed')}};
        if(name==='../security/private-members')return{enabled:()=>{checked++;return true;}};
        throw new Error('Unexpected dependency');
    }};
    vm.runInNewContext(fs.readFileSync(filename,'utf8'),sandbox,{filename});
    await sandbox.module.exports.execute({guild:{id:'9000000000000000002'},showModal:async value=>{modal=value;}},{});
    assert.equal(checked,1);assert.match(JSON.stringify(modal.toJSON()),/consentimentos válidos/);
});
