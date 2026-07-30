require('dotenv').config();
const { Client, GatewayIntentBits, Collection } = require('discord.js');
const express = require('express');
const path = require('path');
const fs = require('fs');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
    ]
});

client.commands = new Collection();

// Load Events
const eventsPath = path.join(__dirname, 'src/events');
if (fs.existsSync(eventsPath)) {
    const eventFiles = fs.readdirSync(eventsPath).filter(file => file.endsWith('.js'));
    for (const file of eventFiles) {
        const filePath = path.join(eventsPath, file);
        const event = require(filePath);
        if (event.once) {
            client.once(event.name, (...args) => event.execute(...args, client));
        } else {
            client.on(event.name, (...args) => event.execute(...args, client));
        }
    }
}

// Load Commands
const commandsPath = path.join(__dirname, 'src/commands');
if (fs.existsSync(commandsPath)) {
    const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));
    for (const file of commandFiles) {
        const filePath = path.join(commandsPath, file);
        const command = require(filePath);
        if (command.data && command.data.name) {
            client.commands.set(command.data.name, command);
        } else if (file === 'handler.js') {
            client.commands.set('handler', command);
        }
    }
}

// Web Server
const app = express();
const PORT = process.env.PORT || 80;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'src/web/public')));

// Simple custom engine to replace <%= variable %> with data
app.engine('html', (filePath, options, callback) => {
    fs.readFile(filePath, (err, content) => {
        if (err) return callback(err);
        let rendered = content.toString();
        for (let key in options) {
            if (typeof options[key] === 'string' || typeof options[key] === 'number') {
                const regex = new RegExp(`<%= ${key} %>`, 'g');
                rendered = rendered.replace(regex, options[key]);
            }
        }
        return callback(null, rendered);
    });
});

app.set('views', path.join(__dirname, 'src/web/views'));
app.set('view engine', 'html');

// Import Web Routes
require('./src/web/server')(app, client);

client.login(process.env.TOKEN).catch(err => {
    console.error('Failed to login to Discord:', err.message);
});

app.listen(PORT, () => {
    console.log(`Web server running on port ${PORT}`);
});
