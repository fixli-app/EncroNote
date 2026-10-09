param(
  [string]$ApkPath = "android\app\build\outputs\apk\release\app-release.apk"
)

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sourceApk = if ([System.IO.Path]::IsPathRooted($ApkPath)) {
  $ApkPath
} else {
  Join-Path $repoRoot $ApkPath
}

if (-not (Test-Path -LiteralPath $sourceApk -PathType Leaf)) {
  throw "Release APK not found: $sourceApk. Build a signed release APK first."
}

$apksigner = Get-Command "apksigner" -ErrorAction SilentlyContinue
if (-not $apksigner) {
  throw "Android SDK apksigner was not found on PATH. Add the Android SDK build-tools directory to PATH."
}

& $apksigner.Source verify --verbose $sourceApk
if ($LASTEXITCODE -ne 0) {
  throw "APK signature verification failed. The installer was not copied."
}

$downloadDirectory = Join-Path $repoRoot "public\downloads"
New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null
$destinationApk = Join-Path $downloadDirectory "EncroNote.apk"
Copy-Item -LiteralPath $sourceApk -Destination $destinationApk -Force
$legacyApk = Join-Path $downloadDirectory "private-notes-android.apk"
if (Test-Path -LiteralPath $legacyApk -PathType Leaf) {
  Remove-Item -LiteralPath $legacyApk -Force
}

Write-Output "Published verified APK to $destinationApk"
