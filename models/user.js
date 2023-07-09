const { Schema, model } = require("mongoose");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const { handleMongooseError } = require("../helpers");

const emailRegexp =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

const userTarif = ["starter", "pro", "business"];

const userSchema = new Schema(
  {
    name: {
      type: String,    
  },
    password: {
      type: String,
      minlength: 6,
      required: [true, "Set password for user"],
    },
    email: {
      type: String,
      match: [emailRegexp, "is not a valid email"],
      required: [true, "Email is required"],
      unique: true,
    },
    subscription: {
      type: String,
      enum: userTarif,
      default: "starter",
    },
    avatarURL: String,
    token: String,
  },
  { versionKey: false }
);
userSchema.methods.setPassword = async function(password){
  this.password = await bcrypt.hash(password, 10);
}
userSchema.methods.comparePassword = async function(password){
  return await bcrypt.compare(password, this.password);
} 

userSchema.post("save", handleMongooseError);

const schemaJoiRegister = Joi.object({
  name: Joi.string().required(),
  password: Joi.string().min(6).required(),
  email: Joi.string().pattern(emailRegexp).required(),
  subscription: Joi.string().validate(...userTarif),
  token: Joi.string(),
});

const schemaJoiLogin = Joi.object({
  name: Joi.string(),
  password: Joi.string().min(6).required(),
  email: Joi.string().pattern(emailRegexp).required(),
});

const schemaJoiCurrentUser = Joi.object({
  email: Joi.string().pattern(emailRegexp),
  token: Joi.string().required(),
});

const schemaJoiUpdate = Joi.object({
  subscription: Joi.string().valid(...userTarif),
});

const schemaJoiEmail = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
})

const schemas = {
  schemaJoiRegister,
  schemaJoiUpdate,
  schemaJoiLogin,
  schemaJoiCurrentUser,
  schemaJoiEmail,
};
const User = model("user", userSchema);

module.exports = { User, schemas };
