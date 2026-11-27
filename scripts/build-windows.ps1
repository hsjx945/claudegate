param(
  [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$StageDir = Join-Path $RootDir "build\win\ClaudeGate"
$EngineDir = Join-Path $StageDir "engine"
$RuntimeDir = Join-Path $StageDir "runtime"
$ZipPath = Join-Path $RootDir "build\ClaudeGate-$Version-windows-x64.zip"

Write-Host "1) Building TypeScript engine..."
Push-Location $RootDir
try {
  npm run build
  if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
} finally {
  Pop-Location
}

Write-Host "2) Preparing staging directory $StageDir..."
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path $StageDir, $EngineDir, $RuntimeDir | Out-Null

Write-Host "3) Generating ClaudeGate.ico..."
$IcoPath = Join-Path $RootDir "build\win\ClaudeGate.ico"
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 64, 64
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)
$pts = [System.Drawing.Point[]]@(
  (New-Object System.Drawing.Point 32, 4),
  (New-Object System.Drawing.Point 56, 14),
  (New-Object System.Drawing.Point 54, 34),
  (New-Object System.Drawing.Point 32, 58),
  (New-Object System.Drawing.Point 10, 34),
  (New-Object System.Drawing.Point 8, 14)
)
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$path.AddPolygon($pts)
$brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(15, 23, 42))
$g.FillPath($brush, $path)
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(56, 189, 248)), 3
$g.DrawPath($pen, $path)
$dotBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(16, 185, 129))
$g.FillEllipse($dotBrush, 22, 22, 20, 20)
$g.Dispose()
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$fs = New-Object System.IO.FileStream($IcoPath, [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()
$bmp.Dispose()

Write-Host "4) Compiling native Windows Tray executable (ClaudeGate.exe)..."
$csc = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
  throw "C# compiler not found at $csc"
}
$exeOut = Join-Path $StageDir "ClaudeGate.exe"
& $csc /nologo /target:winexe /optimize+ "/win32icon:$IcoPath" `
  /reference:System.Windows.Forms.dll,System.Drawing.dll,System.Web.Extensions.dll `
  "/out:$exeOut" `
  (Join-Path $RootDir "windows\ClaudeGateTray.cs")
if ($LASTEXITCODE -ne 0) { throw "csc.exe compilation failed" }

Write-Host "5) Copying engine & bundling portable node.exe..."
Copy-Item -Recurse (Join-Path $RootDir "dist") (Join-Path $EngineDir "dist")
Copy-Item -Recurse (Join-Path $RootDir "public") (Join-Path $EngineDir "public")
Copy-Item (Join-Path $RootDir "package.json") (Join-Path $EngineDir "package.json")

$nodeSrc = (Get-Command node.exe).Source
Copy-Item $nodeSrc (Join-Path $RuntimeDir "node.exe")
& (Join-Path $RuntimeDir "node.exe") -e "import('node:sqlite').then(() => console.log('SQLITE_OK'))"
if ($LASTEXITCODE -ne 0) { throw "Portable node.exe node:sqlite verification failed" }

Write-Host "6) Creating Windows release archive $ZipPath..."
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path "$StageDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
Write-Host "Built $ZipPath"
