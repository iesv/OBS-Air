$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).ProviderPath
if ((Get-Item -LiteralPath $taskRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Refusing a linked workspace'
}
Add-Type -AssemblyName Microsoft.VisualBasic
function Remove-TaskTemporary([string]$taskPath) {
    if (-not (Test-Path -LiteralPath $taskPath)) { return }
    $taskResolved = (Resolve-Path -LiteralPath $taskPath).ProviderPath
    if (-not $taskResolved.StartsWith($taskRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Cleanup target is outside workspace: $taskResolved"
    }
    $taskItem = Get-Item -LiteralPath $taskResolved
    if ($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing linked cleanup target: $taskResolved"
    }
    if ($taskItem.PSIsContainer) {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($taskResolved,
            [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
            [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
            [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    } else {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($taskResolved,
            [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
            [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
            [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException)
    }
}
foreach ($taskRelative in @('.deps', 'build', 'scripts/__pycache__', 'tests/__pycache__')) {
    Remove-TaskTemporary (Join-Path $taskRoot $taskRelative)
}
$taskVersion = [regex]::Match((Get-Content -LiteralPath (Join-Path $taskRoot 'CMakeLists.txt') -Raw),
    'project\(OBS-Air VERSION ([0-9.]+)').Groups[1].Value
$taskLatest = @("OBS-Air-$taskVersion-windows-x64.zip", "OBS-Air-$taskVersion-macos-arm64.zip")
$taskDist = Join-Path $taskRoot 'dist'
if (Test-Path -LiteralPath $taskDist) {
    if ((Get-Item -LiteralPath $taskDist).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing a linked dist directory'
    }
    # Retain old ZIPs until both replacement packages have arrived.
    if ((Test-Path -LiteralPath (Join-Path $taskDist $taskLatest[0])) -and
        (Test-Path -LiteralPath (Join-Path $taskDist $taskLatest[1]))) {
        foreach ($taskItem in (Get-ChildItem -LiteralPath $taskDist -Filter 'OBS-Air-*')) {
            if ($taskItem.Name -notin $taskLatest) { Remove-TaskTemporary $taskItem.FullName }
        }
    }
}
Write-Host 'Temporary files removed. Source, workflows, Git metadata and latest installation ZIPs preserved.'
