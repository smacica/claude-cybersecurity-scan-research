//ingredients used to be plain strings. they are now {emoji, text}, so both shapes
//have to survive a round trip - old rows are still in the database.
//
//written as esm and shared by both sides: vite imports it through the @shared alias,
//the express side reaches it with require(), which node supports for esm modules.
export const DEFAULT_EMOJI = '🥄'

//first match wins, so the longer words sit above the ones they contain
const EMOJI_RULES = [
  [/\b(olive oil|oil)\b/i, '🫒'],
  [/\b(spring onion|scallion|leek)\b/i, '🧅'],
  [/\b(onion|shallot)\b/i, '🧅'],
  [/\b(garlic)\b/i, '🧄'],
  [/\b(tomato|passata)\b/i, '🍅'],
  [/\b(potato)\b/i, '🥔'],
  [/\b(carrot)\b/i, '🥕'],
  [/\b(pepper|paprika|chilli|chili)\b/i, '🌶️'],
  [/\b(aubergine|eggplant)\b/i, '🍆'],
  [/\b(courgette|zucchini|cucumber)\b/i, '🥒'],
  [/\b(broccoli)\b/i, '🥦'],
  [/\b(mushroom)\b/i, '🍄'],
  [/\b(corn|sweetcorn|polenta)\b/i, '🌽'],
  [/\b(salad|lettuce|spinach|rocket|kale)\b/i, '🥬'],
  [/\b(avocado)\b/i, '🥑'],
  [/\b(lemon)\b/i, '🍋'],
  [/\b(lime)\b/i, '🍈'],
  [/\b(orange)\b/i, '🍊'],
  [/\b(apple)\b/i, '🍎'],
  [/\b(banana)\b/i, '🍌'],
  [/\b(strawberr|berry|berries)/i, '🍓'],
  [/\b(grape|wine)\b/i, '🍇'],
  [/\b(coconut)\b/i, '🥥'],
  [/\b(peanut|nut|almond|walnut|cashew)\b/i, '🥜'],
  [/\b(bean|lentil|chickpea)s?\b/i, '🫘'],
  [/\b(rice|risotto)\b/i, '🍚'],
  [/\b(pasta|spaghetti|noodle|macaroni|penne)\b/i, '🍝'],
  [/\b(bread|baguette|toast|breadcrumb)/i, '🍞'],
  [/\b(flour|dough|semolina)\b/i, '🌾'],
  [/\b(egg)s?\b/i, '🥚'],
  [/\b(milk|cream|yoghurt|yogurt|buttermilk)\b/i, '🥛'],
  [/\b(butter|ghee)\b/i, '🧈'],
  [/\b(cheese|parmesan|mozzarella|feta|cheddar)\b/i, '🧀'],
  [/\b(chicken|turkey|poultry)\b/i, '🍗'],
  [/\b(beef|steak|mince|lamb|pork|bacon|ham|sausage)\b/i, '🥩'],
  [/\b(fish|salmon|tuna|cod|anchov)/i, '🐟'],
  [/\b(prawn|shrimp|crab|lobster)\b/i, '🦐'],
  [/\b(salt)\b/i, '🧂'],
  [/\b(sugar|honey|syrup)\b/i, '🍯'],
  [/\b(water|stock|broth)\b/i, '💧'],
  [/\b(chocolate|cocoa)\b/i, '🍫'],
  [/\b(coffee|espresso)\b/i, '☕'],
  [/\b(tea)\b/i, '🍵'],
  [/\b(basil|herb|parsley|thyme|rosemary|coriander|cilantro|mint|oregano)\b/i, '🌿'],
  [/\b(spice|cumin|curry|cinnamon|turmeric|ginger)\b/i, '✨']
]

//best guess from the wording, used as the default before anyone picks one
export function suggestEmoji(text){
  const match = EMOJI_RULES.find(([pattern]) => pattern.test(text || ''))
  return match ? match[1] : DEFAULT_EMOJI
}

//accepts a string, a {emoji, text} object, or junk, and always returns the object
export function normaliseIngredient(value){
  if(value && typeof value === 'object'){
    const text = String(value.text ?? '').trim()
    if(!text){
      return null
    }
    const emoji = String(value.emoji ?? '').trim()
    return { emoji: emoji || suggestEmoji(text), text }
  }

  const text = String(value ?? '').trim()
  if(!text){
    return null
  }
  return { emoji: suggestEmoji(text), text }
}

export function normaliseIngredients(list){
  if(!Array.isArray(list)){
    return []
  }
  return list.map(normaliseIngredient).filter(Boolean)
}

//a small palette for the picker, so nobody has to hunt through a full emoji keyboard
export const EMOJI_PALETTE = [
  '🥄', '🍅', '🧅', '🧄', '🥕', '🥔', '🌶️', '🍆', '🥒', '🥬',
  '🥦', '🍄', '🌽', '🥑', '🍋', '🍊', '🍎', '🍌', '🍓', '🍇',
  '🥥', '🥜', '🫘', '🍚', '🍝', '🍞', '🌾', '🥚', '🥛', '🧈',
  '🧀', '🍗', '🥩', '🐟', '🦐', '🧂', '🍯', '💧', '🍫', '🌿',
  '🫒', '☕', '🍵', '✨'
]
