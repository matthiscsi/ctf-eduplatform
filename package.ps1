param(
  [string]$Output = "..\ctf-suite.zip"
)

# Run from inside the ctf-suite folder
Compress-Archive -Path * -DestinationPath $Output -Force
Write-Host "Packaged to $Output"
