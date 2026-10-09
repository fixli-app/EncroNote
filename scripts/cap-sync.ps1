$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

& npm.cmd run build
if ($LASTEXITCODE -ne 0) {
  throw "Website build failed with exit code $LASTEXITCODE."
}

$apkInWebBuild = Join-Path $repoRoot 'dist\downloads\private-notes-android.apk'
if (Test-Path -LiteralPath $apkInWebBuild -PathType Leaf) {
  Remove-Item -LiteralPath $apkInWebBuild -Force
}

& npx.cmd cap sync
if ($LASTEXITCODE -ne 0) {
  throw "Capacitor sync failed with exit code $LASTEXITCODE."
}
