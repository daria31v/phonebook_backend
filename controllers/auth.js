const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");
const { nanoid } = require("nanoid");

require("dotenv").config();

const { User } = require("../models/user");
const { SECRET_KEY } = process.env;
const { HttpError, ctrWrapper } = require("../helpers");

const avatarDir = path.join(__dirname, "../", "public", "avatars");

const register = async (req, res) => {
  const {name, email, password } = req.body;

  const user = await User.findOne({ email });
  if (user) {
    throw HttpError(409);
  }
  // const hashPassword = await bcrypt.hash(password, 10);
  const avatarURL = gravatar.url(email);

  const newUser = new User({
    name,
    email,
    password,
    avatarURL,
  });

  await newUser.setPassword(password);

  const token = jwt.sign({_id: newUser.id}, SECRET_KEY, { expiresIn: "3d" }); 
  newUser.token = token;
   newUser.save();

  res.status(201).json({
    token,
    user: {
      name: newUser.name,
      email: newUser.email,
      avatarURL: newUser.avatarURL,      
    },
  });
};

const login = async (req, res) => {
  const {email, password } = req.body;
  const user = await User.findOne({ email });
  console.log(user);
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }

  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password is wrong");
  }
  const playload = {
    id: user._id,
    
  };  

  const token = jwt.sign(playload, SECRET_KEY, { expiresIn: "3d" });
  await User.findByIdAndUpdate(user._id, { token });

  res.status(200).json({
    token,
    user: {
      name: user.name,
      email: user.email,
      avatarURL: user.avatarURL,
      subscription: user.subscription
    },
  });
};

const getCurrent = async (req, res) => {
  const { name, email, avatarURL, subscription, token } = req.user;
  if (!token) {
    throw HttpError(401, "Not authorized");
  }
  res.status(200).json({ name, email, avatarURL, subscription });
};

const logout = async (req, res) => {
  const { _id } = req.user;
  console.log(_id);
  const resultLogout = await User.findByIdAndRemove(_id, { token: "" });
  if (!resultLogout) {
    throw HttpError(401, "Not authorized");
  }
  res.status(204).json("");
};

const updateSubscription = async (req, res) => {
  const { token } = req.user;
  const result = await User.findOneAndUpdate(token, req.body, { new: true });
  if (!result) {
    throw HttpError(404);
  }
  res.status(200).json({
    user: {
      email: result.email,
      subscription: result.subscription,
    },
  });
};

const updateAvatar = async (req, res) => {
  const { token } = req.user;
  const { path: tempUpload, originalname } = req.file;
  const nanoidId = nanoid(3);
  const extention = path.extname(originalname);
  const basename = path.basename(originalname, extention);
  const newName = basename + "-" + nanoidId + extention;
  const filename = `${newName}`;
  const resultUpload = path.join(avatarDir, filename);
  await fs.rename(tempUpload, resultUpload);

  const avatarURL = path.join("avatars", filename);
  await User.findOneAndUpdate({ token }, { avatarURL });

  (async function () {
    const image = await Jimp.read(resultUpload);
    image.resize(250, 250);
    image.write(resultUpload);
  })();

  res.status(200).json({
    avatarURL,
  });
};

module.exports = {
  register: ctrWrapper(register),
  login: ctrWrapper(login),
  logout: ctrWrapper(logout),
  getCurrent: ctrWrapper(getCurrent),
  updateSubscription: ctrWrapper(updateSubscription),
  updateAvatar: ctrWrapper(updateAvatar),
};
