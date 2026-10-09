import { copyFile, rm } from 'node:fs/promises'
import { resolve, sep } from 'node:path'

const projectRoot = process.cwd()
const outputDirectory = resolve(projectRoot, 'dist')
const sourcePage = resolve(projectRoot, 'public', 'download.html')
const homePage = resolve(outputDirectory, 'index.html')
const appAssets = resolve(outputDirectory, 'assets')

if (!homePage.startsWith(`${outputDirectory}${sep}`) || !appAssets.startsWith(`${outputDirectory}${sep}`)) {
  throw new Error('Refusing to prepare the Android site outside the Vite output directory.')
}

await copyFile(sourcePage, homePage)
await rm(appAssets, { recursive: true, force: true })
