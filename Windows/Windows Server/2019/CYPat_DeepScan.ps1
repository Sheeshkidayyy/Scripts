<#
.SYNOPSIS
  Read-only deep scan for media, document, archive, script and executable files on Windows Server.

.DESCRIPTION
  Non-destructive scanner that enumerates common locations on all filesystem drives (Users, ProgramData,
  Program Files, Program Files (x86), and the drive root) and logs any files matching a configurable set
  of extensions. Does NOT modify, move, or delete files — it only reports them.

.PARAMETER ScanRoots
  Optional list of drive roots to scan (e.g., C:\, D:\). If omitted the script auto-discovers filesystem drives.

.PARAMETER ExtraPaths
  Additional paths to include in the scan.

.PARAMETER ExcludePaths
  Paths to exclude (prefix-match, case-insensitive). Defaults to system folders.

.PARAMETER ReportPath
  Path to the output report file. Defaults to $env:TEMP\cypat_prohibited_scan_report.txt

.PARAMETER IncludeHidden
  Include hidden and system files/folders in enumeration.

.PARAMETER Parallel
  If supplied, will attempt parallel processing per-root using Start-Job for isolation. Use on machines with many cores.

.EXAMPLE
  .\CYPat_DeepScan.ps1
  Run default scan (auto-detect drives and default exclusions).

.EXAMPLE
  .\CYPat_DeepScan.ps1 -ScanRoots C:\,D:\ -ExtraPaths "E:\Shared" -ReportPath "C:\temp\scan.txt"
#>

param(
    [string[]]$ScanRoots,
    [string[]]$ExtraPaths = @(),
    [string[]]$ExcludePaths = @($env:SystemRoot, $env:ProgramFiles, $env:'ProgramFiles(x86)'),
    [string]$ReportPath = (Join-Path $env:TEMP "cypat_prohibited_scan_report.txt"),
    [switch]$IncludeHidden,
    [switch]$Parallel
)

function Find-ProhibitedFiles {
    param(
        [string[]]$ScanRootsParam,
        [string[]]$ExtraPathsParam,
        [string[]]$ExcludePathsParam,
        [string]$OutFile,
        [switch]$IncludeHiddenParam
    )

    Write-Host "`n--- STARTING EXPANDED DEEP SCAN FOR MEDIA, SCRIPTS & EXECUTABLES (READ-ONLY) ---" -ForegroundColor Magenta

    # Extension categories (without leading dot)
    $videoExt   = @("mp4","avi","mov","mkv","wmv","flv","mpg","mpeg","m4v","webm","3gp","3g2","ts","m2ts","ogv","vob")
    $audioExt   = @("mp3","wav","m4a","flac","aac","ogg","wma","aiff","alac","opus")
    $scriptExt  = @("ps1","psm1","bat","cmd","vbs","vbe","js","jse","wsf","wsh","py","pl","rb","php","sh","psd1")
    $imageExt   = @("jpg","jpeg","png","gif","bmp","tiff","svg","webp","heic")
    $archiveExt = @("zip","rar","7z","tar","gz","bz2","xz","iso","msi")
    $documentExt= @("doc","docx","xls","xlsx","ppt","pptx","pdf","odt","ods","odp","rtf","txt","csv","md","tex")
    $exeExt     = @("exe","dll","bin","com","msi","scr","sys")

    $allExtensions = ($videoExt + $audioExt + $scriptExt + $imageExt + $archiveExt + $documentExt + $exeExt) | Sort-Object -Unique

    # Build initial scan paths from roots
    $scanPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $ScanRootsParam) {
        if (-not $root) { continue }
        $candidates = @(
            (Join-Path $root "Users"),
            (Join-Path $root "ProgramData"),
            (Join-Path $root "Program Files"),
            (Join-Path $root "Program Files (x86)"),
            $root.TrimEnd('\')
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

        foreach ($p in $candidates) { $scanPaths.Add($p) }
    }

    foreach ($p in $ExtraPathsParam) { if ($p -and (Test-Path $p)) { $scanPaths.Add($p) } }

    # Apply prefix-based exclusions (case-insensitive)
    $scanPaths = $scanPaths | Where-Object {
        $exclude = $false
        foreach ($ex in $ExcludePathsParam) {
            if (-not $ex) { continue }
            if ($_.StartsWith($ex, [System.StringComparison]::InvariantCultureIgnoreCase)) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -Unique

    if (-not $scanPaths -or $scanPaths.Count -eq 0) {
        Write-Host "No valid scan paths found after applying excludes. Exiting." -ForegroundColor Yellow
        return
    }

    # Initialize report
    Set-Content -Path $OutFile -Value ("Prohibited file scan report - {0}`nScan started: {1}`n`nScan paths: {2}`nPatterns: {3}`nResults:`n" -f (Get-Date -Format o), (Get-Date), ($scanPaths -join ', '), ($allExtensions -join ', ')) -Encoding UTF8

    # Counters
    $counts = [ordered]@{ Scripts=0; Media=0; Images=0; Archives=0; Documents=0; Executables=0; Other=0; Errors=0 }

    foreach ($rootPath in $scanPaths) {
        Write-Host "`nScanning: $rootPath" -ForegroundColor Cyan
        try {
            $getChildParams = @{ Path = $rootPath; Recurse = $true; File = $true; ErrorAction = 'SilentlyContinue' }
            if ($IncludeHiddenParam) { $getChildParams['Force'] = $true }

            $items = Get-ChildItem @getChildParams
            if (-not $items) { continue }

            foreach ($file in $items) {
                try {
                    $extNoDot = $file.Extension.TrimStart('.').ToLower()
                    if ([string]::IsNullOrEmpty($extNoDot)) { continue }

                    if ($scriptExt -contains $extNoDot) {
                        Write-Host "[POTENTIAL SCRIPT] $($file.FullName)" -ForegroundColor Red
                        Add-Content -Path $OutFile -Value ("[SCRIPT] {0}" -f $file.FullName)
                        $counts.Scripts++
                    }
                    elseif ($videoExt -contains $extNoDot -or $audioExt -contains $extNoDot) {
                        Write-Host "[MEDIA] $($file.FullName)" -ForegroundColor Yellow
                        Add-Content -Path $OutFile -Value ("[MEDIA] {0}" -f $file.FullName)
                        $counts.Media++
                    }
                    elseif ($imageExt -contains $extNoDot) {
                        Write-Host "[IMAGE] $($file.FullName)" -ForegroundColor Cyan
                        Add-Content -Path $OutFile -Value ("[IMAGE] {0}" -f $file.FullName)
                        $counts.Images++
                    }
                    elseif ($archiveExt -contains $extNoDot) {
                        Write-Host "[ARCHIVE] $($file.FullName)" -ForegroundColor Magenta
                        Add-Content -Path $OutFile -Value ("[ARCHIVE] {0}" -f $file.FullName)
                        $counts.Archives++
                    }
                    elseif ($documentExt -contains $extNoDot) {
                        Write-Host "[DOCUMENT] $($file.FullName)" -ForegroundColor Gray
                        Add-Content -Path $OutFile -Value ("[DOCUMENT] {0}" -f $file.FullName)
                        $counts.Documents++
                    }
                    elseif ($exeExt -contains $extNoDot) {
                        Write-Host "[EXECUTABLE] $($file.FullName)" -ForegroundColor DarkRed
                        Add-Content -Path $OutFile -Value ("[EXECUTABLE] {0}" -f $file.FullName)
                        $counts.Executables++
                    }
                    elseif ($allExtensions -contains $extNoDot) {
                        Write-Host "[OTHER MATCH] $($file.FullName)" -ForegroundColor White
                        Add-Content -Path $OutFile -Value ("[OTHER] {0}" -f $file.FullName)
                        $counts.Other++
                    }
                } catch {
                    $counts.Errors++
                    $msg = ("Error processing file {0}: {1}" -f $file.FullName, $_.Exception.Message)
                    Add-Content -Path $OutFile -Value $msg
                }
            }
        } catch {
            Write-Warning "Failed to recursively enumerate $rootPath : $_"
            Add-Content -Path $OutFile -Value ("Failed to enumerate path {0}: {1}" -f $rootPath, $_.Exception.Message)
        }
    }

    # Summary
    Add-Content -Path $OutFile -Value "`nSummary:`n"
    foreach ($k in $counts.Keys) {
        $line = "{0,-12} : {1}" -f $k, $counts[$k]
        Add-Content -Path $OutFile -Value $line
    }

    Write-Host "`nSearch Complete. Summary:" -ForegroundColor Magenta
    $counts.GetEnumerator() | ForEach-Object { Write-Host ("{0,-12} : {1}" -f $_.Name, $_.Value) }
    Write-Host "Full report saved to: $OutFile" -ForegroundColor Green
    Write-Host "CRITICAL: Do NOT delete files unless you are 100% sure they are prohibited." -ForegroundColor White
}

# --- Main execution ---
# Determine scan roots
if ($ScanRoots -and $ScanRoots.Count -gt 0) {
    $finalScanRoots = $ScanRoots
} else {
    $finalScanRoots = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Root })
}

if ($Parallel) {
    # Lightweight parallelization: run each root in a separate job (helps on machines with many cores)
    $jobs = @()
    foreach ($r in $finalScanRoots) {
        $j = Start-Job -ScriptBlock {
            param($root,$extra,$excl,$out,$includeHidden)
            Find-ProhibitedFiles -ScanRootsParam @($root) -ExtraPathsParam $extra -ExcludePathsParam $excl -OutFile $out -IncludeHiddenParam:$includeHidden
        } -ArgumentList ($r,$ExtraPaths,$ExcludePaths,$ReportPath,$IncludeHidden.IsPresent)
        $jobs += $j
    }
    Write-Host "Started $($jobs.Count) jobs; waiting for completion..." -ForegroundColor Cyan
    Receive-Job -Job $jobs -Wait -AutoRemoveJob | Out-Null
} else {
    Find-ProhibitedFiles -ScanRootsParam $finalScanRoots -ExtraPathsParam $ExtraPaths -ExcludePathsParam $ExcludePaths -OutFile $ReportPath -IncludeHiddenParam:$IncludeHidden
}

Write-Host "`nDone." -ForegroundColor Green