const multer  = require('multer')
const path = require('path')

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './data/recipes_pics');
  },
  filename: function (req, file, cb) {
    //generateRecipeId put the id on the request, so the photo is named after its recipe
    cb(null, req.recipeId + path.extname(file.originalname).toLowerCase())
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    cb(null, file.mimetype.startsWith('image/'))
  }
});
module.exports = {upload}
