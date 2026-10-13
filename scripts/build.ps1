param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    python scripts/prepare.py
    if ($LASTEXITCODE) { throw 'Dependency preparation failed' }

    $taskCMake = Join-Path $taskRoot '.deps/tools/cmake/data/bin/cmake.exe'
    if (-not (Test-Path -LiteralPath $taskCMake)) {
        python -m pip install --disable-pip-version-check --target .deps/tools cmake==4.4.4
        if ($LASTEXITCODE) { throw 'CMake installation failed' }
    }
    $taskVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    $taskVsRoot = & $taskVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $taskVsRoot) { throw 'Visual Studio C++ x64 build tools are required' }
    $taskEnvScript = Join-Path $taskRoot '.deps/msvc-env.cmd'
    @"
@echo off
call "$taskVsRoot\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
set
"@ | Set-Content -LiteralPath $taskEnvScript -Encoding ascii
    # Some desktop launchers quote PATH entries. cmd.exe requires the quotes removed.
    $env:Path = $env:Path.Replace('"', '')
    $env:VSCMD_SKIP_SENDTELEMETRY = '1'
    $taskEnvironment = & $env:ComSpec /d /c $taskEnvScript
    if ($LASTEXITCODE) { throw 'MSVC environment initialization failed' }
    foreach ($taskLine in $taskEnvironment) {
        if ($taskLine -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }

    if (-not (Test-Path -LiteralPath '.deps/openssl/lib/libcrypto.lib')) {
        Write-Host 'Building OpenSSL 3.5.9 (static crypto)'
        $taskPerl = Join-Path $taskRoot '.deps/strawberry/perl/bin/perl.exe'
        $taskPrefix = (Join-Path $taskRoot '.deps/openssl').Replace('\', '/')
        $taskJom = Join-Path $taskRoot '.deps/jom/jom.exe'
        $taskOpenSSLLog = Join-Path $taskRoot '.deps/openssl-build.log'
        Push-Location '.deps/openssl-source'
        try {
            $env:_CL_ = '/MD /FS'
            & $taskPerl Configure VC-WIN64A no-asm no-shared no-tests no-module "--prefix=$taskPrefix" *> $taskOpenSSLLog
            if ($LASTEXITCODE) { throw 'OpenSSL configuration failed' }
            & $taskJom -j 8 build_libs *>> $taskOpenSSLLog
            if ($LASTEXITCODE) { throw 'OpenSSL compilation failed' }
            & nmake /nologo install_dev *>> $taskOpenSSLLog
            if ($LASTEXITCODE) { throw 'OpenSSL installation failed' }
        } catch {
            Get-Content -LiteralPath $taskOpenSSLLog -Tail 30
            throw
        } finally {
            Remove-Item Env:_CL_ -ErrorAction SilentlyContinue
            Pop-Location
        }
    }
    python scripts/package_licenses.py windows build/THIRD_PARTY_LICENSES.txt
    if ($LASTEXITCODE) { throw 'License packaging failed' }
    & $taskCMake --preset windows-x64
    if ($LASTEXITCODE) { throw 'CMake configuration failed' }
    & $taskCMake --build --preset windows-x64 --parallel 8
    if ($LASTEXITCODE) { throw 'Compilation failed' }
    if (-not $SkipTests) {
        & (Join-Path (Split-Path $taskCMake) 'ctest.exe') --preset windows-x64
        if ($LASTEXITCODE) { throw 'Tests failed' }
    }
    & (Join-Path (Split-Path $taskCMake) 'cpack.exe') --config build/CPackConfig.cmake -C Release -B build/package
    if ($LASTEXITCODE) { throw 'Packaging failed' }
    $taskPackage = Get-ChildItem -LiteralPath 'build/package' -Filter 'OBS-Air-*-windows-x64.zip' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    New-Item -ItemType Directory -Path dist -Force | Out-Null
    Copy-Item -LiteralPath $taskPackage.FullName -Destination dist -Force
    Add-Type -AssemblyName Microsoft.VisualBasic
    foreach ($taskOldPackage in (Get-ChildItem -LiteralPath dist -Filter 'OBS-Air-*-windows-x64.zip' -File |
        Where-Object Name -NE $taskPackage.Name)) {
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($taskOldPackage.FullName,
            [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
            [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
    }
} finally {
    Pop-Location
}
