const mysql = require('mysql2');

//connection 
const pool = mysql.createPool({
    host: localhost,
    user: root,
    password: process.env.DB_PASSWORD,
    database: authapi,
})


module.exports = pool.promise();
