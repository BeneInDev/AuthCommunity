const { JsonDatabase } = require("wio.db");
const path = require('path');

const config = new JsonDatabase({
  databasePath: path.join(__dirname, "../DataBaseJson/config.json")
});

const users = new JsonDatabase({
  databasePath: path.join(__dirname, "../DataBaseJson/users.json")
});

const message = new JsonDatabase({
  databasePath: path.join(__dirname, "../DataBaseJson/message.json")
});

module.exports = {
  config,
  users,
  message
}
