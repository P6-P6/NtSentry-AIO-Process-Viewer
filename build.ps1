param([ValidateSet('check','test','build','release','clippy','fetch')][string]$Task = 'release')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
# Git for Windows ships an unrelated link.exe; require the MSVC linker specifically.
$taskLinker = Get-Command link.exe -ErrorAction SilentlyContinue
if (-not $taskLinker -or $taskLinker.Source -notmatch 'Microsoft Visual Studio|MSVC') {
    $taskVsRoots = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})
    $taskVcVars = foreach ($taskVsRoot in $taskVsRoots) {
        Get-ChildItem -Path (Join-Path $taskVsRoot 'Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat') -ErrorAction SilentlyContinue
    }
    $taskVcVars = $taskVcVars | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $taskVcVars) { throw 'Install the Visual Studio C++ build tools and Windows SDK, or run this script from an x64 Native Tools shell.' }
    $taskBuildEnvironment = & cmd.exe /d /c ('"' + $taskVcVars.FullName + '" >nul && set')
    foreach ($taskEnvironmentLine in $taskBuildEnvironment) {
        if ($taskEnvironmentLine -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1],$matches[2],'Process')
        }
    }
}
$taskCargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
if (-not $taskCargo) { $taskCargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe' } else { $taskCargo = $taskCargo.Source }
switch ($Task) {
    'fetch' { & $taskCargo fetch --locked }
    'release' { & $taskCargo build --locked --release }
    'clippy' { & $taskCargo clippy --locked --all-targets -- -D warnings }
    default { & $taskCargo $Task --locked }
}
exit $LASTEXITCODE
