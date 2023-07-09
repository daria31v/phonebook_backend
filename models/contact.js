const { Schema, model } = require("mongoose");
const Joi = require("joi");
const { handleMongooseError } = require("../helpers");

const contactSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Set name for contact"],
    },
    email: {
      type: String,
    },
    number: {
      type: Number,
    },
    owner: {
      type: Schema.Types.ObjectId,
      ref: "user",
      require: true,
    },
    favorite: {
      type: Boolean,
      default: false,
    },
  },
  { versionKey: false }
);

contactSchema.post("save", handleMongooseError);

const schemaJoiAdd = Joi.object({
  name: Joi.string().required(),
  number: Joi.number().required(),
});

const schemaJoiUpdate = Joi.object({
  name: Joi.string(),
  email: Joi.string().email({
    minDomainSegments: 2,
    tlds: { allow: ["com", "net", "ua"] },
  }),
  number: Joi.number(),
  favorite: Joi.boolean(),
});

const schemaUpdateFavorite = Joi.object({
  favorite: Joi.boolean().required(),
});

const schemas = { schemaJoiAdd, schemaJoiUpdate, schemaUpdateFavorite };

const Contact = model("contact", contactSchema);

module.exports = { Contact, schemas };
