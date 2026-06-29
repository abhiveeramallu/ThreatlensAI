require("dotenv").config();

const app = require("./app");

const PORT = process.env.PORT || 3000;

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Bot detection demo running on http://localhost:${PORT}`);
});
