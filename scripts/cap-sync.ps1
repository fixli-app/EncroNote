$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

& npm.cmd run build:app
if ($LASTEXITCODE -ne 0) {
  throw "App build failed with exit code $LASTEXITCODE."
}

foreach ($apkName in @('EncroNote.apk', 'private-notes-android.apk')) {
  $apkInWebBuild = Join-Path $repoRoot "dist\downloads\$apkName"
  if (Test-Path -LiteralPath $apkInWebBuild -PathType Leaf) {
    Remove-Item -LiteralPath $apkInWebBuild -Force
  }
}

& npx.cmd cap sync
if ($LASTEXITCODE -ne 0) {
  throw "Capacitor sync failed with exit code $LASTEXITCODE."
}
