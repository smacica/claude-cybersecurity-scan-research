const express = require('express')
const router = express.Router()
const {dbFind, dbRecipes, dbMyRecipes, insertRecipe, dbDeleteRecipe, dbComments, dbAddComment, dbDeleteComment, handlelike, getMostLiked} = require('../db');
const { isLoggedIn } = require('../google_strategy');
const {upload}  = require('../file_uploud')
const uuid = require('uuid').v4
const path = require('path')
const fs = require('fs')
const date = require('../aditional_functions/get_current_date')
const { normaliseIngredients } = require('../shared/ingredients.mjs')
const { generateRecipe, isConfigured: geminiConfigured } = require('../gemini')
const aiQuota = require('../ai_quota')
const { logger } = require('../logger')
const { audit } = require('../audit')

const picsDir = path.join(__dirname, '..', 'data', 'recipes_pics')

//artwork that generated recipes get as their photo. vite copies this folder into
//the build, so the same /ai_pics/... url works in dev and in production.
const aiPicsDir = path.join(__dirname, '..', '..', 'frontend', 'public', 'ai_pics')
let aiPics = []
try{
  aiPics = fs.readdirSync(aiPicsDir).filter(name => /\.(jpe?g|png|webp)$/i.test(name))
}catch(err){
  logger.warn('no ai_pics folder found, generated recipes will have no photo')
}

function randomAiPic(){
  if(!aiPics.length){
    return null
  }
  return '/ai_pics/' + aiPics[Math.floor(Math.random() * aiPics.length)]
}


function generateRecipeId(req, res, next){
  const id = parseInt(uuid(),16)
  req.recipeId = id
  next()
}

//the form sends steps and ingredients as a json array in a multipart field
function parseList(value){
  if(Array.isArray(value)){
    return value
  }
  if(!value){
    return []
  }
  try{
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) ? parsed : [String(parsed)]
  }catch(err){
    return [String(value)]
  }
}

router.post('/api/recipes',isLoggedIn,generateRecipeId, upload.single('image'), function (req, res) {
  if(!req.body.name){
    return res.status(400).json({message: "a recipe needs a name"})
  }

  const recipe  = {
    recipe_id: req.recipeId,
    user_id: req.user.user_id,
    name: req.body.name,
    //no photo means the client draws its own placeholder
    photo: req.file ? "/data/recipes_pics/" + req.file.filename : null,
    info: req.body.info,
    recipe: parseList(req.body.recipe),
    date: date(),
    //accepts plain strings too, and fills in an emoji when none was picked
    ingredients: normaliseIngredients(parseList(req.body.ingredients))
  }

  insertRecipe(recipe).then(()=>{
    audit.recipeCreated(req.log, { userId: req.user.user_id, recipeId: recipe.recipe_id, source: 'manual' })
    res.status(201).json({recipe_id: recipe.recipe_id})
  }).catch(err=>{
    req.log.error({ err }, 'could not save the recipe')
    res.status(500).json({message: "could not save the recipe"})
  })
})


router.delete('/api/recipes/:id',isLoggedIn,(req,res)=>{
  const id = parseInt(req.params.id)
  if(Number.isNaN(id)){
    return res.status(400).json({message: "bad recipe id"})
  }

  dbDeleteRecipe(id, req.user.user_id).then(result=>{
    if(!result.deleted){
      const status = result.reason === 'forbidden' ? 403 : 404
      const message = result.reason === 'forbidden' ? "that is not your recipe" : "recipe not found"
      if(result.reason === 'forbidden'){
        audit.deleteDenied(req.log, { userId: req.user.user_id, recipeId: id, kind: 'recipe' })
      }
      return res.status(status).json({message})
    }
    audit.recipeDeleted(req.log, { userId: req.user.user_id, recipeId: id })

    //the row is gone either way, a leftover file is not worth failing the request over
    if(result.photo){
      fs.unlink(path.join(picsDir, path.basename(result.photo)),(err)=>{
        if(err && err.code !== 'ENOENT'){
          req.log.warn({ err }, 'could not delete the recipe photo')
        }
      })
    }
    res.json({message: "recipe deleted"})
  }).catch(err=>{
    req.log.error({ err }, 'could not delete the recipe')
    res.status(500).json({message: "could not delete the recipe"})
  })
})

/* ---------- ai generation ---------- */

const AI_INGREDIENTS_MAX = 400
const AI_DESCRIPTION_MAX = 200

//how many generations this user has left today
router.get('/api/ai/quota', isLoggedIn, (req, res)=>{
  aiQuota.peek(req.user.user_id).then(quota=>{
    res.json({ ...quota, configured: geminiConfigured() })
  }).catch(err=>{
    req.log.error({ err }, 'could not read the ai quota')
    res.status(500).json({message: "could not read the quota"})
  })
})

//maps a generation failure onto something the page can show
const FAILURES = {
  'not-configured': [503, "AI generation is not set up on this server."],
  'not-food':       [422, "That does not look like a food request, so nothing was generated."],
  'incomplete':     [422, "The model did not return a usable recipe. Try describing the dish differently."],
  'unreadable':     [502, "The model returned something we could not read. Try again."],
  'rate-limited':   [429, "Google's free quota is used up for now. Try again later."],
  'timeout':        [504, "The model took too long to answer. Try again."],
  'unreachable':    [502, "Could not reach the model. Try again."],
  'upstream':       [502, "The model refused the request. Try again."]
}

router.post('/api/recipes/generate', isLoggedIn, generateRecipeId, async (req, res)=>{
  const ingredients = String(req.body.ingredients || '').trim().slice(0, AI_INGREDIENTS_MAX)
  const description = String(req.body.description || '').trim().slice(0, AI_DESCRIPTION_MAX)

  if(!ingredients && !description){
    return res.status(400).json({message: "Tell the model what you have or what you want."})
  }
  if(!geminiConfigured()){
    return res.status(503).json({message: FAILURES['not-configured'][1]})
  }

  try{
    //booked before the call so a burst of requests cannot slip past the free tier
    const slot = await aiQuota.reserve(req.user.user_id)
    if(!slot.ok){
      audit.aiQuotaDenied(req.log, { userId: req.user.user_id, reason: slot.reason })
      return res.status(429).json({message: slot.message, reason: slot.reason})
    }

    const result = await generateRecipe({ ingredients, description })

    if(!result.ok){
      const [status, message] = FAILURES[result.reason] || FAILURES.upstream
      audit.aiRejected(req.log, { userId: req.user.user_id, reason: result.reason })
      return res.status(status).json({message, reason: result.reason})
    }

    const recipe = {
      recipe_id: req.recipeId,
      user_id: req.user.user_id,
      name: result.recipe.title,
      photo: randomAiPic(),
      info: result.recipe.description,
      recipe: result.recipe.steps,
      date: date(),
      ingredients: result.recipe.ingredients
    }

    await insertRecipe(recipe)
    audit.recipeCreated(req.log, { userId: req.user.user_id, recipeId: recipe.recipe_id, source: 'ai' })
    audit.aiGenerated(req.log, { userId: req.user.user_id, remaining: slot.remaining })
    res.status(201).json({ recipe_id: recipe.recipe_id, remaining: slot.remaining })
  }catch(err){
    req.log.error({ err }, 'could not save the generated recipe')
    res.status(500).json({message: "Could not save the generated recipe."})
  }
})

const COMMENT_MAX = 1000

router.get('/api/recipes/:id/comments',(req,res)=>{
  const id = parseInt(req.params.id)
  if(Number.isNaN(id)){
    return res.status(400).json({message: "bad recipe id"})
  }
  dbComments(id).then(comments=>{
    res.json(comments)
  }).catch(err=>{
    req.log.error({ err }, 'could not load the comments')
    res.status(500).json({message: "could not load the comments"})
  })
})

router.post('/api/recipes/:id/comments',isLoggedIn,(req,res)=>{
  const id = parseInt(req.params.id)
  const body = String(req.body.body || '').trim()

  if(Number.isNaN(id)){
    return res.status(400).json({message: "bad recipe id"})
  }
  if(!body){
    return res.status(400).json({message: "write something first"})
  }
  if(body.length > COMMENT_MAX){
    return res.status(400).json({message: `keep it under ${COMMENT_MAX} characters`})
  }

  dbFind('recipes','recipe_id',id).then(recipe=>{
    if(!recipe){
      return res.status(404).json({message: "recipe not found"})
    }
    dbAddComment(id, req.user.user_id, body).then(comment=>{
      res.status(201).json(comment)
    }).catch(err=>{
      req.log.error({ err }, 'could not save the comment')
      res.status(500).json({message: "could not save the comment"})
    })
  }).catch(err=>{
    req.log.error({ err }, 'could not save the comment')
    res.status(500).json({message: "could not save the comment"})
  })
})

router.delete('/api/comments/:comment_id',isLoggedIn,(req,res)=>{
  const id = parseInt(req.params.comment_id)
  if(Number.isNaN(id)){
    return res.status(400).json({message: "bad comment id"})
  }

  dbDeleteComment(id, req.user.user_id).then(result=>{
    if(!result.deleted){
      const status = result.reason === 'forbidden' ? 403 : 404
      const message = result.reason === 'forbidden' ? "that is not your comment" : "comment not found"
      if(result.reason === 'forbidden'){
        audit.deleteDenied(req.log, { userId: req.user.user_id, recipeId: id, kind: 'comment' })
      }
      return res.status(status).json({message})
    }
    res.json({message: "comment deleted"})
  }).catch(err=>{
    req.log.error({ err }, 'could not delete the comment')
    res.status(500).json({message: "could not delete the comment"})
  })
})

router.post('/api/recipes/:recipe_id/like',isLoggedIn,(req,res)=>{
  const like = Number(req.body.like)
  if(like !== 0 && like !== 1){
    return res.status(400).json({message: "like must be 1 or 0"})
  }

  handlelike(req.params.recipe_id, req.user.user_id, like).then((success)=>{
    if(success){
      res.json({action: success})
    }else{
      res.json({err: "unseccessful"})
    }
  }).catch(err=>{
    //without this a rejection left the request open until the browser gave up
    req.log.error({ err }, 'could not record the vote')
    res.status(500).json({message: "could not record the vote"})
  })
})

router.get('/data/recipes_pics/:filename', (req, res) => {
    //basename keeps a crafted filename from walking out of the pictures folder
    res.sendFile(path.join(picsDir, path.basename(req.params.filename)), err => {
      if(err){
        res.status(404).end()
      }
    });
  });
router.get('/api/recipes', (req, res) => {
    getMostLiked().then(data=>{
      res.json(data)
    }).catch(err=>{
      req.log.error({ err }, 'could not load the recipes')
      res.status(500).json({message: "could not load the recipes"})
    })
  });

//has to stay above /api/recipes/:id, otherwise "mine" is read as an id
router.get('/api/recipes/mine',isLoggedIn,(req,res)=>{
    dbMyRecipes(req.user.user_id).then((data)=>{
      res.json(data)
    }).catch(err=>{
      req.log.error({ err }, 'could not load your recipes')
      res.status(500).json({message: "could not load your recipes"})
    })
})

router.get('/api/recipes/:id',(req,res)=>{
    const id = parseInt(req.params.id)
    if(Number.isNaN(id)){
      return res.status(400).json({message: "bad recipe id"})
    }
    dbFind('recipes','recipe_id',id).then(recipe => {
        if(!recipe){
          return res.status(404).json({message: "recipe not found"})
        }
        res.json(recipe)
    }).catch(err=>{
      req.log.error({ err }, 'could not load the recipe')
      res.status(500).json({message: "could not load the recipe"})
    })
})



module.exports = router