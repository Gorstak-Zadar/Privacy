param(
  [Parameter(Mandatory = $false)]
  [string]$SourceBatPath = ''
)

$ErrorActionPreference = 'Stop'

if (-not $SourceBatPath) {
  $selfDir = Split-Path -Parent $PSCommandPath
  $SourceBatPath = Join-Path $selfDir 'privacy-script.bat'
}

if (-not (Test-Path -LiteralPath $SourceBatPath)) {
  throw "Source batch file not found: $SourceBatPath"
}

$OutDir = Split-Path -Parent $SourceBatPath
$RegOut = Join-Path $OutDir 'privacy-reg-tweaks.reg'
$NonRegOut = Join-Path $OutDir 'privacy-nonreg.bat'
$WrapperOut = Join-Path $OutDir 'privacy-fast.bat'

$Lines = Get-Content -LiteralPath $SourceBatPath
Write-Output ("Loaded lines: {0}" -f $Lines.Count)

function Is-ShellBagsRelatedKey([string]$key) {
  if (-not $key) { return $false }
  $k = $key.ToLowerInvariant()
  return (
    $k -like '*\windows\shell\bag*' -or
    $k -like '*\windows\shell\bags*' -or
    $k -like '*\windows\shell\bagmru*' -or
    $k -like '*\windows\shell\bagsmru*' -or
    $k -like '*\windows\shellnoam\bag*' -or
    $k -like '*\windows\shellnoam\bags*' -or
    $k -like '*\windows\shellnoam\bagmru*' -or
    $k -like '*\windows\shellnoam\bagsmru*'
  )
}

function Convert-HivePrefixToLong([string]$key) {
  return ($key `
      -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' `
      -replace '^HKCU\\', 'HKEY_CURRENT_USER\' `
      -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\' `
      -replace '^HKU\\',  'HKEY_USERS\' `
      -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\')
}

function Escape-RegString([string]$s) {
  if ($null -eq $s) { return '' }
  return ($s -replace '\\', '\\\\' -replace '"', '\"')
}

function To-DwordReg([string]$s) {
  if ($null -eq $s) { $s = '' }
  $s = $s.Trim()
  if (-not $s) { return 'dword:00000000' }

  # Support:
  # - hex: 0xFFFFFFFF
  # - signed decimal: -1  (becomes 0xFFFFFFFF)
  # - decimal: 123
  try {
    if ($s -match '^0x[0-9a-fA-F]+$') {
      $u = [Convert]::ToUInt32($s.Substring(2), 16)
      return ('dword:{0:x8}' -f $u)
    }

    if ($s -match '^-?\d+$') {
      $i = [int64]$s
      $u = [uint32]($i -band 0xFFFFFFFF)
      return ('dword:{0:x8}' -f $u)
    }

    throw "Unsupported REG_DWORD data: '$s'"
  } catch {
    throw "Failed to convert REG_DWORD data '$s': $($_.Exception.Message)"
  }
}

function To-MultiSzHex7([string]$s) {
  # reg.exe REG_MULTI_SZ uses \0 between entries.
  $parts = $s -split '\\0'
  # Remove trailing empties from explicit terminators
  $parts = @($parts | Where-Object { $_ -ne '' })
  $joined = ($parts -join "`0") + "`0`0"
  $bytes = [Text.Encoding]::Unicode.GetBytes($joined)
  return 'hex(7):' + (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ',')
}

function Try-ParseRegAddFromLine([string]$line) {
  # Supports both:
  # - direct: reg add "HKCU\..." /v "Name" /t REG_DWORD /d "1" /f
  # - embedded in PS: ... reg add 'HKCU\...' /v 'Name' /t 'REG_DWORD' /d "^""$data"^"" /f

  # Avoid parsing unrelated lines that merely *contain* "reg add" (e.g. script generators).
  if (-not ($line -like 'PowerShell -ExecutionPolicy Unrestricted -Command*' -or $line -match '^\s*reg(\.exe)?\s+add\b')) {
    return $null
  }
  if ($line -notmatch '\breg(\.exe)?\s+add\b') { return $null }

  $key =
    [regex]::Match($line, "reg(\.exe)?\s+add\s+'([^']+)'").Groups[2].Value
  if (-not $key) { $key = [regex]::Match($line, 'reg(\.exe)?\s+add\s+"([^"]+)"').Groups[2].Value }
  if (-not $key) { return $null }
  if (Is-ShellBagsRelatedKey $key) { return $null }

  $value =
    [regex]::Match($line, "/v\s*'([^']+)'").Groups[1].Value
  if (-not $value) { $value = [regex]::Match($line, '/v\s+"([^"]+)"').Groups[1].Value }
  if (-not $value) { return $null }

  $type = [regex]::Match($line, '/t\s+(?:\x27|\x22)?(REG_[A-Z0-9_]+)(?:\x27|\x22)?').Groups[1].Value
  if (-not $type) { return $null }
  $type = $type.ToUpperInvariant()

  # Data extraction
  $data = $null
  if ($line -like 'PowerShell -ExecutionPolicy Unrestricted -Command*') {
    $m = [regex]::Match($line, '\$data\s*=\s*''([^'']*)''')
    if ($m.Success) { $data = $m.Groups[1].Value }
    if ($null -eq $data) {
      $m2 = [regex]::Match($line, '\$data\s*=\s*([-]?\d+|0x[0-9a-fA-F]+)')
      if ($m2.Success) { $data = $m2.Groups[1].Value }
    }
  }
  if ($null -eq $data) {
    # If the reg add uses "$data" inside escaped quotes, we can't reliably recover the value
    # unless it was assigned earlier in the same PowerShell command.
    if ($line -like 'PowerShell -ExecutionPolicy Unrestricted -Command*' -and $line -match '\$data') {
      return $null
    }

    $data =
      [regex]::Match($line, "/d\s*'([^']*)'").Groups[1].Value
    if (-not $data) { $data = [regex]::Match($line, '/d\s+"([^"]*)"').Groups[1].Value }
  }
  if ($null -eq $data) { return $null }

  return [pscustomobject]@{ Key = $key; Value = $value; Type = $type; Data = $data }
}

function Try-ParseValueDelete([string]$line) {
  # Pattern used in the script:
  # $keyName = 'HKCU\...'; $valueName = 'X'; ... Remove-ItemProperty ...
  if ($line -notlike 'PowerShell -ExecutionPolicy Unrestricted -Command*') { return $null }
  if ($line -notmatch 'Remove-ItemProperty|DeleteValue\(') { return $null }

  $keyName = [regex]::Match($line, '\$keyName\s*=\s*''([^'']+)''').Groups[1].Value
  $valueName = [regex]::Match($line, '\$valueName\s*=\s*''([^'']+)''').Groups[1].Value
  if (-not $keyName -or -not $valueName) { return $null }
  if (Is-ShellBagsRelatedKey $keyName) { return $null }

  return [pscustomobject]@{ Key = $keyName; Value = $valueName }
}

function Try-ParseRootKeyClear([string]$line) {
  # Pattern used in the script:
  # $rootRegistryKeyPath = 'HKCU\...'; function Clear-RegistryKeyValues { ... Remove-ItemProperty ...
  if ($line -notlike 'PowerShell -ExecutionPolicy Unrestricted -Command*') { return $null }
  if ($line -notmatch 'rootRegistryKeyPath\s*=') { return $null }
  if ($line -notmatch 'Remove-ItemProperty') { return $null }

  $root = [regex]::Match($line, '\$rootRegistryKeyPath\s*=\s*''([^'']+)''').Groups[1].Value
  if (-not $root) { return $null }
  if (Is-ShellBagsRelatedKey $root) { return $null }
  return $root
}

# Collect entries
$DeleteKeys = New-Object System.Collections.Generic.HashSet[string]
$OpsByKey = @{} # key -> valueName -> op

foreach ($line in $Lines) {
  $add = Try-ParseRegAddFromLine $line
  if ($add) {
    if ($add.Type -in @('REG_DWORD', 'REG_SZ', 'REG_MULTI_SZ')) {
      if (-not $OpsByKey.ContainsKey($add.Key)) { $OpsByKey[$add.Key] = @{} }
      $OpsByKey[$add.Key][$add.Value] = [pscustomobject]@{ Kind = 'set'; Type = $add.Type; Data = $add.Data }
    }
    continue
  }

  $dv = Try-ParseValueDelete $line
  if ($dv) {
    if ($dv.Value -ieq '(default)') {
      # fastest + closest behavior in the script: they delete default value under this key,
      # but deleting the whole key is typically equivalent in these particular cases.
      $DeleteKeys.Add($dv.Key) | Out-Null
    } else {
      if (-not $OpsByKey.ContainsKey($dv.Key)) { $OpsByKey[$dv.Key] = @{} }
      $OpsByKey[$dv.Key][$dv.Value] = [pscustomobject]@{ Kind = 'delete' }
    }
    continue
  }

  $root = Try-ParseRootKeyClear $line
  if ($root) {
    $DeleteKeys.Add($root) | Out-Null
  }
}

# Build .reg
$RegLines = New-Object System.Collections.Generic.List[string]
$RegLines.Add('Windows Registry Editor Version 5.00') | Out-Null
$RegLines.Add('') | Out-Null

foreach ($k in ($DeleteKeys | Sort-Object)) {
  $RegLines.Add('[-' + (Convert-HivePrefixToLong $k) + ']') | Out-Null
  $RegLines.Add('') | Out-Null
}

foreach ($key in ($OpsByKey.Keys | Sort-Object)) {
  if ($DeleteKeys.Contains($key)) { continue } # key deletion wins

  $RegLines.Add('[' + (Convert-HivePrefixToLong $key) + ']') | Out-Null
  $valueMap = $OpsByKey[$key]
  foreach ($valueName in ($valueMap.Keys | Sort-Object)) {
    $op = $valueMap[$valueName]
    $name =
      if ($valueName -ieq '(default)') { '@' }
      else { '"' + (Escape-RegString $valueName) + '"' }

    if ($op.Kind -eq 'delete') {
      if ($valueName -ieq '(default)') {
        # Prefer deleting whole key for default value (already handled elsewhere); skip here.
        continue
      }
      $RegLines.Add($name + '=-') | Out-Null
      continue
    }

    switch ($op.Type) {
      'REG_DWORD' { $RegLines.Add($name + '=' + (To-DwordReg $op.Data)) | Out-Null }
      'REG_SZ' { $RegLines.Add($name + '="' + (Escape-RegString $op.Data) + '"') | Out-Null }
      'REG_MULTI_SZ' { $RegLines.Add($name + '=' + (To-MultiSzHex7 $op.Data)) | Out-Null }
    }
  }
  $RegLines.Add('') | Out-Null
}

[IO.File]::WriteAllLines($RegOut, $RegLines, [Text.Encoding]::Unicode)

# Build non-reg .bat (remove all registry-related lines we migrated)
$Non = New-Object System.Collections.Generic.List[string]
$skipFast = $false
foreach ($line in $Lines) {
  if ($line -match '^::+\s+Fast path:') { $skipFast = $true; continue }
  if ($skipFast) {
    if ($line -match '^:privacy_main') { $skipFast = $false }
    continue
  }

  if ($line -like 'PowerShell -ExecutionPolicy Unrestricted -Command*' -and $line -like '*reg add*') { continue }
  if ($line -match '^\s*reg(\.exe)?\s+add\b') { continue }
  if ($line -like 'PowerShell -ExecutionPolicy Unrestricted -Command*' -and $line -match 'Remove-ItemProperty|DeleteValue\(|rootRegistryKeyPath') { continue }
  $Non.Add($line) | Out-Null
}
[IO.File]::WriteAllLines($NonRegOut, $Non, [Text.Encoding]::Default)

# Wrapper: import once, then run non-reg steps
$Wrapper = @(
  '@echo off',
  'setlocal EnableExtensions DisableDelayedExpansion',
  'fltmc >nul 2>&1 || (',
  '  echo Administrator privileges are required.',
  '  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath ''%~f0'' -Verb RunAs" 2>nul || (',
  '    echo Right-click and Run as administrator.',
  '    pause & exit /b 1',
  '  )',
  '  exit /b 0',
  ')',
  'echo --- Importing registry tweaks',
  'reg import "%~dp0privacy-reg-tweaks.reg" >nul',
  'echo --- Running non-reg steps',
  'call "%~dp0privacy-nonreg.bat"',
  'echo --- Done',
  'pause'
)
[IO.File]::WriteAllLines($WrapperOut, $Wrapper, [Text.Encoding]::Default)

Write-Output "Wrote: $RegOut"
Write-Output "Wrote: $NonRegOut"
Write-Output "Wrote: $WrapperOut"
Write-Output ("Registry keys deleted: {0}" -f $DeleteKeys.Count)
Write-Output ("Registry keys with value ops: {0}" -f $OpsByKey.Keys.Count)

