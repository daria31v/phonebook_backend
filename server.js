const mongoose = require("mongoose");
const app = require("./app");
const chalk = require("chalk");

const { DB_HOST, PORT = 3003 } = process.env;
mongoose
  .connect(DB_HOST)
  .then(() => {
    app.listen(PORT);
    console.log(chalk.bgYellowBright("Database connection successful", PORT));
  })
  .catch((error) => {
    console.log(error.message);
    process.exit(1);
  });
