const validateBodyNewContact = require("./validateBody");
const validateBodyUpdateContact = require("./validateUpdateContact");
const isValidId = require("./isValidId");
const validateBodyNewUser = require("./validateBodyNewUser");
const authentication = require("./authentication");
const validateUpdateUser = require("./validateUpdateUser");
const upload = require("./upload");
const validateVerifyEmail = require("./validateVerifyEmail");
module.exports = {
  validateBodyNewContact,
  validateBodyUpdateContact,
  validateUpdateUser,
  isValidId,
  validateBodyNewUser,
  authentication,
  upload,
  validateVerifyEmail,
};
