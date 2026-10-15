const { JsonDatabase } = require("wio.db");
const path = require('path');

// Importing legacy commands must not read/create JSON in the Supabase-only flow.
// Keep the same API and paths for actual legacy operations.
function lazyDatabase(name) {
  let instance;
  return new Proxy({}, {
    get(_target, property) {
      instance ||= new JsonDatabase({
        databasePath: path.join(__dirname, `../DataBaseJson/${name}.json`)
      });
      const value = Reflect.get(instance, property);
      return typeof value === 'function' ? value.bind(instance) : value;
    }
  });
}

const config = lazyDatabase('config');
const users = lazyDatabase('users');
const message = lazyDatabase('message');

module.exports = {
  config,
  users,
  message
}
