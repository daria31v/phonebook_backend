const { Contact } = require("../models/contact");

const { HttpError, ctrWrapper } = require("../helpers");

const getAll = async (req, res) => {
  const { _id: owner } = req.user;
  const { page = 1, limit = 20, favorite } = req.query;
  const skip = (page - 1) * limit;
  if (favorite) {
    const listFavorite = await Contact.find({ owner, favorite: true }, "", {
      skip,
      limit,
    });
    return res.json(listFavorite);
  }
  const listAll = await Contact.find({ owner }, "", {
    skip,
    limit,
  });

  res.status(200).json(listAll);
};

const getById = async (req, res) => {
  const { contactId } = req.params;
  const dataId = await Contact.findById(contactId);
  if (!dataId) {
    throw HttpError(404, "Not found");
  }
  res.status(200).json(dataId);
};

const addNewContact = async (req, res) => {
  console.log(req.body)
  const { _id: owner } = req.user;
  
  const { name, email, number } = req.body;
  const data = await Contact.create({ ...{ name, email, number }, owner });
  res.status(201).json(data);
};

const updateById = async (req, res) => {
  const id = req.params.contactId;
  const resultUpdate = await Contact.findByIdAndUpdate(id, req.body, {
    new: true,
  });
  const { name, email, number } = req.body;
  if (!resultUpdate) {
    throw HttpError(404, "Not found");
  }
  if (!name && !email && !number) {
    throw HttpError(400, "missing fields");
  }
  res.status(200).json(resultUpdate);
};

const updateFavorite = async (req, res) => {
  const id = req.params.contactId;
  const resultUpdate = await Contact.findByIdAndUpdate(id, req.body, {
    new: true,
  });
  if (!resultUpdate) {
    throw HttpError(404, "Not found");
  }
  res.status(200).json(resultUpdate);
};

const deleteById = async (req, res) => {
  const id = req.params.contactId;
  console.log(id);
  const deleteContact = await Contact.findByIdAndRemove(id);
  if (!deleteContact) {
    throw HttpError(404, "Not found");
  }
  res.status(200).json({ message: "contact deleted" });
};

module.exports = {
  getAll: ctrWrapper(getAll),
  getById: ctrWrapper(getById),
  addNewContact: ctrWrapper(addNewContact),
  updateById: ctrWrapper(updateById),
  updateFavorite: ctrWrapper(updateFavorite),
  deleteById: ctrWrapper(deleteById),
};
