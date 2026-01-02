const mysql = require("mysql2");

// SQL connection (works locally and on Render with env variables)
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",   // use cloud DB host on Render, fallback to localhost
  user: process.env.DB_USER || "root",       // DB username
  password: process.env.DB_PASSWORD || "",   // DB password
  database: process.env.DB_NAME || "ecommerce_app", // DB name
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test the connection
db.getConnection((err, connection) => {
  if (err) {
    console.error("DB Connection Error:", err);
  } else {
    console.log("MySQL Connected successfully");
    connection.release(); // release connection back to pool
  }
});

module.exports = db;
