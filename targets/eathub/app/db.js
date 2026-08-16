const uuid = require('uuid').v4
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs')
const path = require('path')
const { logger } = require('./logger')

//the data folder is gitignored, so create it before sqlite tries to open the db file
const dataDir = path.join(__dirname, 'data')
fs.mkdirSync(path.join(dataDir, 'recipes_pics'), { recursive: true })
const dbPath = path.join(dataDir, 'main.db')

const schemaQuerry = `
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    password TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    profile_pic TEXT,
    bio TEXT
);
CREATE TABLE IF NOT EXISTS email_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recipes (
    recipe_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name TEXT,
    photo TEXT,
    info TEXT,
    recipe TEXT,
    date TEXT,
    ingredients TEXT
);
CREATE TABLE IF NOT EXISTS ranking (
    recipe_id INTEGER PRIMARY KEY REFERENCES recipes(recipe_id) ON DELETE CASCADE,
    likes INTEGER DEFAULT 0,
    dislikes INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS likes (
    like_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id INTEGER REFERENCES recipes(recipe_id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    rating INTEGER
);
CREATE TABLE IF NOT EXISTS comments (
    comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id INTEGER NOT NULL REFERENCES recipes(recipe_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_recipe ON comments(recipe_id);
CREATE TABLE IF NOT EXISTS ai_usage (
    day TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    calls INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, user_id)
);`

//sqlite cannot add a UNIQUE column with ALTER TABLE, so google_id is kept unique
//through an index instead - that also lets several rows stay NULL
const indexQuerry = `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);`

//google accounts are trusted, google already checked the address
const verifyGoogleUsersQuerry = `UPDATE users SET email_verified = 1 WHERE google_id IS NOT NULL AND email_verified = 0;`

//brings an older database up to the current shape
function migrateUsers(){
    return new Promise((resolve, reject) => {
        db.all(`PRAGMA table_info(users);`,(err, columns)=>{
            if(err){
                return reject(new Error(err))
            }
            const names = columns.map(column => column.name)
            const password = columns.find(column => column.name === 'password')
            const steps = []

            if(!names.includes('google_id')){
                steps.push(`ALTER TABLE users ADD COLUMN google_id TEXT;`)
            }
            //the original column was NOT NULL, which blocks google-only accounts.
            //sqlite cannot relax that in place, so drop it and add it back nullable.
            if(password && password.notnull){
                steps.push(`ALTER TABLE users DROP COLUMN password;`)
            }
            if(!password || password.notnull){
                steps.push(`ALTER TABLE users ADD COLUMN password TEXT;`)
            }
            if(!names.includes('email_verified')){
                steps.push(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;`)
            }

            if(!steps.length){
                return resolve()
            }
            db.exec(steps.join('\n'),(err)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    logger.info('users table migrated')
                    resolve()
                }
            })
        })
    })
}

let db = new sqlite3.Database(dbPath, (err) => {

    if(err)
    {
    logger.error({ err }, 'could not open the database')
    }else{
        logger.info('sqlite connected')
        db.get("PRAGMA foreign_keys = ON",(err,data)=>{
            if(err){
                logger.error({ err }, 'could not turn foreign keys on')
            }
        })
        db.exec(schemaQuerry,(err)=>{
            if(err){
                return logger.error({ err }, 'could not apply the schema')
            }
            migrateUsers().then(()=>{
                db.exec(indexQuerry + verifyGoogleUsersQuerry,(err)=>{
                    if(err){
                        logger.error({ err }, 'could not apply the indexes')
                    }
                })
            }).catch(err=>logger.error({ err }, 'could not migrate the users table'))
        })
    }
})

function handlelike(recipe_id, user_id, likeStatement){
    return new Promise((resolve, reject) => {
        let rankComlumn = []
        if(likeStatement == 1){
            rankComlumn = ['likes','dislikes']
        }else if(likeStatement == 0){
            rankComlumn = ['dislikes', 'likes']
        }else{
            //without the return this carried on and ran the queries below with an
            //undefined column name, which left the request hanging
            return reject(new Error("like must be 1 or 0"))
        }

        const findRecordQuery = `SELECT * FROM likes 
        WHERE recipe_id=? AND user_id=?;`
        db.all(findRecordQuery, [recipe_id, user_id],(err,data)=>{
            if(err){
                reject(new Error(err))
            }else if(data.length>0){
                if(data[0].rating == likeStatement){
                    const delQuerry = `DELETE FROM likes WHERE like_id =?;`
                db.run(delQuerry,[data[0].like_id],(err)=>{
                    if(err){
                        reject(new Error(err)) 
                    }else{
                        dbUpdate('ranking', 'recipe_id', recipe_id, rankComlumn[0], '-1').then(()=>{
                            resolve("cancel")
                        })
                    }
                })
                }else{
                    const updateQuery = `UPDATE likes SET rating = ? WHERE like_id = ?`
                    db.run(updateQuery, [likeStatement, data[0].like_id],(err, data)=>{
                        if(err){
                            reject(new Error(err)) 
                        }else{
                            dbUpdate('ranking', 'recipe_id', recipe_id, rankComlumn[0], '+1').then(()=>{
                                dbUpdate('ranking', 'recipe_id', recipe_id, rankComlumn[1], '-1').then(()=>{
                                    resolve("change")
                                })
                            })
        
                        }
                    })
                }
                      
            }else{
                const createQuery = `INSERT INTO likes(recipe_id, user_id, rating)
                VALUES(?, ?, ?)`
                db.run(createQuery, [recipe_id, user_id, likeStatement],(err)=>{
                    if(err){
                        reject(new Error(err)) 
                    }else{
                        dbUpdate('ranking', 'recipe_id', recipe_id, rankComlumn[0], '+1').then(()=>{
                            resolve("add")
                        })
                    }
                })
            }
        })
    })
}

async function getRecipes(data){
    const recipes = []

    for(const rank of data){
        const recipe = await dbFind("recipes","recipe_id",rank.recipe_id)

        //a ranking row can outlive its recipe when something deleted the recipe on a
        //connection without foreign keys on. skip it instead of dying on the whole list.
        if(!recipe){
            logger.warn({ recipeId: rank.recipe_id }, 'ranking row has no recipe, skipping')
            continue
        }

        recipe.likes = rank.likes
        recipe.dislikes = rank.dislikes
        recipes.push(recipe)
    }

    return recipes
}

const mostLikedQuerry = `SELECT * FROM ranking ORDER BY likes DESC;`
function getMostLiked(){
    return new Promise((resolve, reject) => {
        db.all(mostLikedQuerry,(err, data)=>{
            if(err){
                reject(new Error(err))
            }else{
                getRecipes(data).then(resolve).catch(err=>reject(new Error(err)))
            }
        })
    })
}

const recipeQuerry = `INSERT INTO 
recipes (recipe_id,user_id, name, photo, info, recipe, date, ingredients)
 VALUES(?,?,?,?,?,?,DATE(?),?);`
const recipeRankingQuerry = `INSERT INTO 
ranking (recipe_id, likes, dislikes, views) 
VALUES(?,?,?,?);`
function insertRecipe(recipe){
    return new Promise((resolve, reject) => {
        const id = parseInt(uuid(),16)
        db.run(recipeQuerry ,[recipe.recipe_id,recipe.user_id, recipe.name, recipe.photo, recipe.info, JSON.stringify(recipe.recipe),recipe.date,JSON.stringify(recipe.ingredients) ], (err , data) => {
            if(err){
                reject(new Error(err))      
            }else{
                db.run(recipeRankingQuerry, [recipe.recipe_id, 0, 0, 0],(err, data)=>{
                    if(err){
                        reject(new Error(err))
                    }else{
                        resolve()
                    }
                })
            }
            });
    })
} 

//only the author may delete. ranking and likes rows go with it through
//ON DELETE CASCADE, so this is a single statement.
function dbDeleteRecipe(recipe_id, user_id){
    return new Promise((resolve, reject) => {
        dbFind('recipes','recipe_id',recipe_id).then(recipe=>{
            if(!recipe){
                return resolve({ deleted: false, reason: 'missing' })
            }
            if(recipe.user_id !== user_id){
                return resolve({ deleted: false, reason: 'forbidden' })
            }
            db.run(`DELETE FROM recipes WHERE recipe_id = ?;`,[recipe_id],(err)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    resolve({ deleted: true, photo: recipe.photo })
                }
            })
        }).catch(err=>reject(new Error(err)))
    })
}

/* ---------- ai usage ---------- */

//user_id 0 is the row that counts every call, whoever made it
const TOTAL_ROW = 0

//how many calls have gone out today, in total and for this one user
function dbAiUsage(day, user_id){
    return new Promise((resolve, reject) => {
        db.all(`SELECT user_id, calls FROM ai_usage WHERE day = ? AND user_id IN (?, ?);`,
        [day, TOTAL_ROW, user_id],(err, rows)=>{
            if(err){
                return reject(new Error(err))
            }
            const find = id => rows.find(row => row.user_id === id)?.calls || 0
            resolve({ total: find(TOTAL_ROW), user: find(user_id) })
        })
    })
}

//counted before the call goes out, so a crash mid-request cannot leak free quota
function dbAiUsageIncrement(day, user_id){
    const bump = `INSERT INTO ai_usage(day, user_id, calls) VALUES(?,?,1)
    ON CONFLICT(day, user_id) DO UPDATE SET calls = calls + 1;`
    return new Promise((resolve, reject) => {
        db.run(bump,[day, TOTAL_ROW],(err)=>{
            if(err){
                return reject(new Error(err))
            }
            db.run(bump,[day, user_id],(err)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    resolve()
                }
            })
        })
    })
}

/* ---------- comments ---------- */

//joined so the list carries the author's name and picture in one round trip
const commentsQuerry = `SELECT c.comment_id, c.recipe_id, c.user_id, c.body, c.created_at,
u.username, u.profile_pic
FROM comments c JOIN users u ON u.user_id = c.user_id
WHERE c.recipe_id = ?
ORDER BY c.created_at DESC;`
function dbComments(recipe_id){
    return new Promise((resolve, reject) => {
        db.all(commentsQuerry,[recipe_id],(err, rows)=>{
            if(err){
                reject(new Error(err))
            }else{
                resolve(rows)
            }
        })
    })
}

function dbAddComment(recipe_id, user_id, body){
    return new Promise((resolve, reject) => {
        const created_at = Date.now()
        db.run(`INSERT INTO comments(recipe_id, user_id, body, created_at) VALUES(?,?,?,?);`,
        [recipe_id, user_id, body, created_at], function(err){
            if(err){
                return reject(new Error(err))
            }
            db.all(commentsQuerry.replace('WHERE c.recipe_id = ?','WHERE c.comment_id = ?'),[this.lastID],(err, rows)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    resolve(rows[0])
                }
            })
        })
    })
}

//a comment can be removed by whoever wrote it or by the owner of the recipe
function dbDeleteComment(comment_id, user_id){
    return new Promise((resolve, reject) => {
        db.all(`SELECT c.comment_id, c.user_id, r.user_id AS recipe_owner
        FROM comments c JOIN recipes r ON r.recipe_id = c.recipe_id
        WHERE c.comment_id = ? LIMIT 1;`,[comment_id],(err, rows)=>{
            if(err){
                return reject(new Error(err))
            }
            const row = rows[0]
            if(!row){
                return resolve({ deleted: false, reason: 'missing' })
            }
            if(row.user_id !== user_id && row.recipe_owner !== user_id){
                return resolve({ deleted: false, reason: 'forbidden' })
            }
            db.run(`DELETE FROM comments WHERE comment_id = ?;`,[comment_id],(err)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    resolve({ deleted: true })
                }
            })
        })
    })
}

const likeQuerry = `INSERT INTO
 likes (user_id, recipe_id)
 values(?,?);`
function addLike(user, recipe){
    return new Promise((resolve, reject) => {
        db.run(likeQuerry,[user, recipe],(err, data)=>{
            if(err){
                reject(new Error(err))
            }else{
                resolve()
            }
        })
    })
}

const selectQuery = 'SELECT * FROM recipes;'
function dbRecipes(){
    return new Promise((resolve, reject) => {
        db.all(selectQuery , (err , data) => {
            if(err){
                reject(new Error(err))      
            }else{
                resolve(data)
            }
            });
    })
}

async function addLikesToMyRecipes(data){
    const finalResult = []

    //sequential rather than forEach(async ...), which used to resolve on whichever
    //lookups happened to finish first and left the order up to chance
    for(const recipe of data){
        const rating = await dbFind('ranking','recipe_id',recipe.recipe_id)
        //a recipe with no ranking row just has no votes yet
        recipe.likes = rating?.likes ?? 0
        recipe.dislikes = rating?.dislikes ?? 0
        finalResult.push(recipe)
    }

    return finalResult
}

function dbMyRecipes(user_id){
    return new Promise((resolve, reject) => {
        dbFind('recipes', 'user_id', user_id, false, false, 'all').then((data, err)=>{
            if(err){
                reject(new Error(err))
            }else{
                addLikesToMyRecipes(data).then(resolve).catch(err=>reject(new Error(err)))
            }
        })
    })
}

const userCreateQuery = `INSERT INTO users(google_id, username, email, password, email_verified, profile_pic, bio) VALUES(?,?,?,?,?,?,?)
`
function dbCreateUser(data){
    return new Promise((resolve, reject) => {
        const values = [
            data.google_id || null,
            data.username,
            data.email,
            data.password || null,
            data.email_verified ? 1 : 0,
            data.profile_pic || null,
            data.bio
        ]
        db.run(userCreateQuery ,values, function(err){
            if(err){
                reject(new Error(err))
            }else{
                resolve(this.lastID)
            }
            });
    })
}

//emails are compared lowercase so Ann@x.com and ann@x.com cannot both sign up
function dbFindByEmail(email){
    return new Promise((resolve, reject) => {
        db.all(`SELECT * FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1;`,[email],(err, data)=>{
            if(err){
                reject(new Error(err))
            }else{
                resolve(data[0])
            }
        })
    })
}

//one live token per user, so asking for a new mail invalidates the older link
function dbCreateEmailToken(user_id, token, expires){
    return new Promise((resolve, reject) => {
        db.run(`DELETE FROM email_tokens WHERE user_id = ?;`,[user_id],(err)=>{
            if(err){
                return reject(new Error(err))
            }
            db.run(`INSERT INTO email_tokens(token, user_id, expires) VALUES(?,?,?);`,[token, user_id, expires],(err)=>{
                if(err){
                    reject(new Error(err))
                }else{
                    resolve(token)
                }
            })
        })
    })
}

//marks the address confirmed and burns the token, returns the user or null
function dbConsumeEmailToken(token){
    return new Promise((resolve, reject) => {
        db.all(`SELECT * FROM email_tokens WHERE token = ? LIMIT 1;`,[token],(err, rows)=>{
            if(err){
                return reject(new Error(err))
            }
            const row = rows[0]
            if(!row){
                return resolve(null)
            }
            db.run(`DELETE FROM email_tokens WHERE token = ?;`,[token],(err)=>{
                if(err){
                    return reject(new Error(err))
                }
                if(row.expires < Date.now()){
                    return resolve({ expired: true })
                }
                db.run(`UPDATE users SET email_verified = 1 WHERE user_id = ?;`,[row.user_id],(err)=>{
                    if(err){
                        return reject(new Error(err))
                    }
                    dbFind('users','user_id',row.user_id).then(resolve).catch(err=>reject(new Error(err)))
                })
            })
        })
    })
}

//usernames are unique, so a second "Anna" becomes "Anna2", then "Anna3", ...
async function uniqueUsername(preferred){
    const base = (preferred || 'cook').trim().slice(0, 40) || 'cook'
    let candidate = base
    let suffix = 1
    while(await dbFind('users','username',candidate)){
        suffix += 1
        candidate = `${base}${suffix}`
    }
    return candidate
}

//one entry point for google sign in: match on google_id, fall back to the email
//of an older password account, otherwise create the user
async function dbFindOrCreateGoogleUser(profile){
    const byGoogleId = await dbFind('users','google_id',profile.google_id)
    if(byGoogleId){
        return byGoogleId
    }

    if(profile.email){
        const byEmail = await dbFindByEmail(profile.email)
        if(byEmail){
            //link the existing account to google instead of making a duplicate.
            //google vouches for the address, so the account counts as verified.
            await dbUpdate('users','user_id',byEmail.user_id,'google_id',profile.google_id)
            await dbUpdate('users','user_id',byEmail.user_id,'email_verified','1')
            if(profile.profile_pic){
                await dbUpdate('users','user_id',byEmail.user_id,'profile_pic',profile.profile_pic)
            }
            return dbFind('users','user_id',byEmail.user_id)
        }
    }

    const username = await uniqueUsername(profile.username || (profile.email || '').split('@')[0])
    const user_id = await dbCreateUser({
        google_id: profile.google_id,
        username,
        email: profile.email,
        email_verified: true,
        profile_pic: profile.profile_pic,
        bio: 'Just joined EatHub.'
    })
    return dbFind('users','user_id',user_id)
}

//signup with an address and a password - unverified until the emailed link is opened
async function dbCreateLocalUser({ email, password, username }){
    const taken = await dbFindByEmail(email)
    if(taken){
        return null
    }
    const name = await uniqueUsername(username || email.split('@')[0])
    const user_id = await dbCreateUser({
        username: name,
        email,
        password,
        email_verified: false,
        bio: 'Just joined EatHub.'
    })
    return dbFind('users','user_id',user_id)
}

function dbFind(table,column, value, column2=false, value2=false, limit = 1){
    return new Promise((resolve, reject) => {
        let findQuerry = `SELECT * FROM ${table} WHERE ${column}=?`
        let values = [value]
        if (column2 && value2){
            values.push(value2)
            findQuerry = `SELECT * FROM ${table} WHERE ${column}=? AND ${column2}=?`
        }
        if(limit != 'all'){
            findQuerry += ` LIMIT ${limit};`
        }
        db.all(findQuerry ,values, (err , data) => {
            if(err){
                reject(new Error(err))      
            }else{
                if(limit == 1){
                    resolve(data[0])
                }else if(limit != 'all'){
                    resolve(data.slice(0,limit))
                }else{
                    resolve(data)
                }               
            }
            });
    })
}
function dbUpdate(table, conditionColumn, conditionValue, setColumn, setValue){
    return new Promise((resolve, reject) => {
        let updateQuery = `UPDATE ${table} 
        SET ${setColumn}= ?
        WHERE ${conditionColumn} = ?;`

        if (setValue[0] == '+' || setValue[0] == '-'){
            const operator = setValue[0];
            setValue = parseInt(setValue.slice(1))
            updateQuery = `UPDATE ${table} 
            SET ${setColumn}= ${setColumn} ${operator} ?
            WHERE ${conditionColumn} = ?;`
        }

        db.run(updateQuery,[setValue, conditionValue],(err, data)=>{
            if(err){
                reject(new Error(err))
            }else{
                resolve()
            }
        })
    })
}
function dbDel(table,column, value, column2=false, value2=false){
    return new Promise((resolve, reject) => {
        let delQuerry = `DELETE FROM ${table} WHERE ${column}=?;`
        let values = [value]
        if (column2 && value2){
            values.push(value2)
            delQuerry = `SELECT * FROM ${table} WHERE ${column}=? AND ${column2}=?
            LIMIT 1;`
        }
        db.run(delQuerry ,values, (err , data) => {
            if(err){
                reject(new Error(err))      
            }else{
                resolve()
            }
            });
    })
}

module.exports = { dbUpdate, dbDel, dbRecipes, dbFind, dbFindByEmail, dbCreateUser, dbCreateLocalUser, dbFindOrCreateGoogleUser, dbCreateEmailToken, dbConsumeEmailToken, insertRecipe, dbMyRecipes, dbDeleteRecipe, dbComments, dbAddComment, dbDeleteComment, dbAiUsage, dbAiUsageIncrement, addLike, getMostLiked, handlelike }