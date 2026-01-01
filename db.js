const mysql = require("mysql2");

// sql connection
 const db = mysql.createConnection({
    host :"localhost",
    user :"root",
    password :"",
    database :"ecommerce_app"
 });

//  connect

db.connect(err =>{
    if (err) console.log("DB Connection Error:", err);
    else console.log("MySQL Connected successfully");
})
module.exports = db;


