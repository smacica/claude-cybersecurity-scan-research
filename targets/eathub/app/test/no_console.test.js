const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')

const root = path.join(__dirname, '..')
const SKIP_DIRS = new Set(['node_modules', 'frontend', '.git', 'data', 'test', '.idea', '.vscode'])

//the verification-link fallback in mailer.js is deliberate developer output:
//it has to stay readable and must not be filtered out by LOG_LEVEL. only that
//specific line in mailer.js is exempt, not the whole file, since mailer.js also
//handles email addresses. exemption requires both file name and content check.
const ALLOWED_CONTENT = 'verification link for'
const ALLOWED_FILE = 'mailer.js'

function backendFiles(dir = root, found = []){
  for(const entry of fs.readdirSync(dir, { withFileTypes: true })){
    if(entry.isDirectory()){
      if(!SKIP_DIRS.has(entry.name)) backendFiles(path.join(dir, entry.name), found)
    }else if(entry.name.endsWith('.js') || entry.name.endsWith('.mjs')){
      found.push(path.join(dir, entry.name))
    }
  }
  return found
}

test('backend code logs through the logger, not console', () => {
  const offenders = []

  for(const file of backendFiles()){
    const relative = path.relative(root, file)

    fs.readFileSync(file, 'utf8').split('\n').forEach((line, index) => {
      if(/console\.\w+\(/.test(line) && !(file.endsWith(ALLOWED_FILE) && line.includes(ALLOWED_CONTENT))){
        offenders.push(`${relative}:${index + 1}`)
      }
    })
  }

  assert.deepStrictEqual(offenders, [], `use logger or req.log instead of console at: ${offenders.join(', ')}`)
})
