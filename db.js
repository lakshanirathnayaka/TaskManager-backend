const { Pool } = require("pg");

const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: "PSQL123@",
  db: "postgres",
  port: 5432
});

module.exports = pool;
