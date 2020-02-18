
    [cmdletbinding()]
    Param(
        [string]$BEARER1,
        [string]$BEARER2,
        [string]$TWEETSFILE,
        [switch]$NOAPICALL=$true,
        [switch]$DONT_REENCODE_VIDEOS=$true
    )
    if($TWEETSFILE){
        $LINKS = @()
        $LINKS += [System.IO.File]::ReadAllLines($TWEETSFILE)
    }
    Function RelCom
    {
        param($ComObject)
        $ret=1
        while($ret -gt 0){
            try {
                $ret=[System.Runtime.Interopservices.Marshal]::ReleaseComObject($comobject)
            }
            catch [System.Management.Automation.MethodInvocationException]{
                break
            }
        }
    }
    Function AddAllAssemblies
    {
        Param()
        @(
            "System.Net",
            "System.Net.Http",
            "Microsoft.VisualBasic",
            "Microsoft.mshtml",
            "System.Security.Cryptography.ProtectedData"
        ).forEach({
            $ASMNAME = $_
            Remove-Variable DLLPATH,NONUGET -ea 0
            if (!("$($ASMNAME)"-as [type])){
                try{
                    Add-Type -AssemblyName "$($ASMNAME)" -ea 0
                    if($?){ 
                        Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                        Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                        Write-Host "loaded successfully by name" -ForegroundColor Yellow
                    }
                }
                catch {
                    $e = $_
                    Write-Host "Add-Type: $($e.FullyQualifiedErrorId.split(',')[0]) " -ForegroundColor red -NoNewline
                    Write-Host "thrown wile attempting to add " -ForegroundColor Yellow -NoNewline
                    Write-Host "$($ASMNAME)" -ForegroundColor Green
                    $DLLPATH = gci "C:\Windows\assembly\" -Recurse "*$($ASMNAME).dll" -ea 0 | % fullName
                    if(!$DLLPATH){
                        $DLLPATH = gci "C:\Program Files (x86)\Reference Assemblies" -Recurse "*$($ASMNAME).dll" -ea 0 | % fullName
                        if(!$DLLPATH){
                            $DLLPATH = gci "C:\Program Files\Reference Assemblies" -Recurse "*$($ASMNAME).dll" -ea 0 | % fullName
                            if(!$DLLPATH){
                                Remove-Variable reqasm,EX,test -ea 0
                                while(!$test){
                                    try {
                                        $test = iwr google.com -ea 0
                                    } 
                                    catch [System.NotSupportedException]{
                                        if(!$ans){
                                            $ans = [Microsoft.VisualBasic.Interaction]::MsgBox(
                                                "You will need to open Internet Explorer and complete the 'first run' wizard.",
                                                [Microsoft.VisualBasic.MsgBoxStyle]::OkOnly,
                                                "Twitter Web Scraping Machine"
                                            )
                                        }
                                        if(!$iexplore){
                                            . "C:\program files\internet Explorer\iexplore.exe"
                                            while((get-process iexplore -ea 0)){
                                                sleep -m 200
                                            }
                                            $iexplore = $true
                                        }
                                    }
                                }
                                Write-Host "Could not locate DLL file for $($ASMNAME)" -ForegroundColor Yellow
                                if($ASMNAME -eq "Microsoft.mshtml"){
                                    $NONUGET = $true
                                    $DLLINK = "https://download.visualstudio.microsoft.com/download/pr/32bd116c-8f5d-45f8-96df-9d26c953f457/18986661a190d9319bdb3648f2349ae2/payload.vsix"
                                    $FILE = "C:\Temp\mshtml\payload.vsix"
                                    $FOLDER = "C:\Temp\mshtml\payload\"
                                    if([System.IO.Directory]::Exists($FOLDER)){
                                        remove-item $FOLDER -recurse -force -ea 0
                                    }
                                    if([System.IO.File]::Exists($FILE)){
                                        Remove-Item $FILE -ea 0
                                    }
                                    $null = [System.IO.Directory]::CreateDirectory($FOLDER)
                                    ([System.Net.WebClient]::New()).DownloadFile($DLLINK,$FILE)
                                    $7ZOUT = cmd /c "`"C:\Program Files\7-Zip\7z.exe`" x `"$($FILE)`" -y -o`"$($FOLDER)`" * 2>&1"
                                    $DLLFILE = gci -Recurse $FOLDER "*$($ASMNAME).dll" | % FullName
                                    Add-type -Path $DLLFILE
                                }
                                if(!$NONUGET){
                                    Write-Host "Attempting to resolve nuget package" -ForegroundColor Yellow
                                    try {
                                        $reqasm = iwr "https://www.nuget.org/packages/$($ASMNAME)" -ea 0
                                    }
                                    catch [System.Net.WebException] {
                                        $EX = @()
                                        $_.Exception | % { $EX += $_ }
                                    }
                                    if($reqasm) {
                                        $DLLPATH = Install-DotNet_nupkg -URI "https://www.nuget.org/packages/$($ASMNAME)/"
                                        Add-Type -Path $DLLPATH -ea 0
                                        if("$($ASMNAME)"-as [type]){
                                            Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                                            Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                                            Write-Host "loaded successfully via nuget package" -ForegroundColor yellow
                                        }
                                    }
                                    if(!$reqasm) {
                                        Write-Host "Nuget package unavailable" -ForegroundColor red
                                        Write-Host "Cannot load type $($ASMNAME)" -ForegroundColor Yellow
                                    }
                                }
                            } else {
                                Add-Type -path $DLLPATH -ea 0
                                if(("$($ASMNAME)"-as [type])){
                                    Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                                    Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                                    Write-Host "loaded successfully by DLL file" -ForegroundColor Yellow 
                                }
                            }
                        } else {
                            Add-Type -path $DLLPATH -ea 0
                            if("$($ASMNAME)"-as [type]) {
                                Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                                Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                                Write-Host "loaded successfully by DLL file" -ForegroundColor Yellow 
                            }
                        }
                    } else {
                        Add-Type -path $DLLPATH -ea 0
                        if("$($ASMNAME)"-as [type]){
                            Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                            Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                            Write-Host "loaded successfully by DLL file" -ForegroundColor Yellow 
                        }
                    }
                }
            } else {
                Write-Host "Assembly: " -ForegroundColor Yellow -NoNewline
                Write-Host "$($ASMNAME) " -ForegroundColor Green -NoNewline
                Write-Host "is already loaded" -ForegroundColor Yellow
            }
        })
    }
    Function SetConsoleOptions
    {
        Param()
        Add-Type -TypeDefinition @"
        namespace Windows.Native
        {
        using System;
        using System.ComponentModel;
        using System.IO;
        using System.Runtime.InteropServices;
        
        public class Kernel32
        {
          // Constants
          ////////////////////////////////////////////////////////////////////////////
          public const uint FILE_SHARE_READ = 1;
          public const uint FILE_SHARE_WRITE = 2;
          public const uint GENERIC_READ = 0x80000000;
          public const uint GENERIC_WRITE = 0x40000000;
          public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
          public const int STD_ERROR_HANDLE = -12;
          public const int STD_INPUT_HANDLE = -10;
          public const int STD_OUTPUT_HANDLE = -11;
    
          // Structs
          ////////////////////////////////////////////////////////////////////////////
          [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
          public class CONSOLE_FONT_INFOEX
          {
            private int cbSize;
            public CONSOLE_FONT_INFOEX()
            {
              this.cbSize = Marshal.SizeOf(typeof(CONSOLE_FONT_INFOEX));
            }
    
            public int FontIndex;
            public short FontWidth;
            public short FontHeight;
            public int FontFamily;
            public int FontWeight;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string FaceName;
          }
    
          public class Handles
          {
            public static readonly IntPtr StdIn = GetStdHandle(STD_INPUT_HANDLE);
            public static readonly IntPtr StdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            public static readonly IntPtr StdErr = GetStdHandle(STD_ERROR_HANDLE);
          }
          
          // P/Invoke function imports
          ////////////////////////////////////////////////////////////////////////////
          [DllImport("kernel32.dll", SetLastError=true)]
          public static extern bool CloseHandle(IntPtr hHandle);
          
          [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
          public static extern IntPtr CreateFile
            (
            [MarshalAs(UnmanagedType.LPTStr)] string filename,
            uint access,
            uint share,
            IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
            );
            
          [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
          public static extern bool GetCurrentConsoleFontEx
            (
            IntPtr hConsoleOutput, 
            bool bMaximumWindow, 
            // the [In, Out] decorator is VERY important!
            [In, Out] CONSOLE_FONT_INFOEX lpConsoleCurrentFont
            );
            
          [DllImport("kernel32.dll", SetLastError=true)]
          public static extern IntPtr GetStdHandle(int nStdHandle);
          
          [DllImport("kernel32.dll", SetLastError=true)]
          public static extern bool SetCurrentConsoleFontEx
            (
            IntPtr ConsoleOutput, 
            bool MaximumWindow,
            // Again, the [In, Out] decorator is VERY important!
            [In, Out] CONSOLE_FONT_INFOEX ConsoleCurrentFontEx
            );
          
          
          // Wrapper functions
          ////////////////////////////////////////////////////////////////////////////
          public static IntPtr CreateFile(string fileName, uint fileAccess, 
            uint fileShare, FileMode creationDisposition)
          {
            IntPtr hFile = CreateFile(fileName, fileAccess, fileShare, IntPtr.Zero, 
              creationDisposition, 0U, IntPtr.Zero);
            if (hFile == INVALID_HANDLE_VALUE)
            {
              throw new Win32Exception();
            }
    
            return hFile;
          }
    
          public static CONSOLE_FONT_INFOEX GetCurrentConsoleFontEx()
          {
            IntPtr hFile = IntPtr.Zero;
            try
            {
              hFile = CreateFile("CONOUT$", GENERIC_READ,
              FILE_SHARE_READ | FILE_SHARE_WRITE, FileMode.Open);
              return GetCurrentConsoleFontEx(hFile);
            }
            finally
            {
              CloseHandle(hFile);
            }
          }
    
          public static void SetCurrentConsoleFontEx(CONSOLE_FONT_INFOEX cfi)
          {
            IntPtr hFile = IntPtr.Zero;
            try
            {
              hFile = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, FileMode.Open);
              SetCurrentConsoleFontEx(hFile, false, cfi);
            }
            finally
            {
              CloseHandle(hFile);
            }
          }
    
          public static CONSOLE_FONT_INFOEX GetCurrentConsoleFontEx
            (
            IntPtr outputHandle
            )
          {
            CONSOLE_FONT_INFOEX cfi = new CONSOLE_FONT_INFOEX();
            if (!GetCurrentConsoleFontEx(outputHandle, false, cfi))
            {
              throw new Win32Exception();
            }
    
            return cfi;
          }
        }
        }
"@
        $cfi = [Windows.Native.Kernel32]::GetCurrentConsoleFontEx()
        $cfi.FontHeight = 14
        $cfi.FontWidth = 8
        [Windows.Native.Kernel32]::SetCurrentConsoleFontEx($cfi)
        [System.Console]::BackgroundColor = "Black"
        [System.Console]::ForegroundColor = "Yellow"
        [System.Console]::Clear()
        $HOST.ui.RawUI.WindowTitle = "Welcome to my Twitter scraping machine!!"
        MoveWindowOver -SIDE 'RIGHT' -THIS_WINDOW ; sleep -s 2; [System.Console]::BufferWidth = 1000; [System.Console]::clear();
        write-host "`n"
    write-host @"
      _______       _ _   _             __          __  _        _____                                
     |__   __|     (_) | | |            \ \        / / | |      / ____|                               
        | |_      ___| |_| |_ ___ _ __   \ \  /\  / /__| |__   | (___   ___ _ __ __ _ _ __   ___ _ __ 
        | \ \ /\ / / | __| __/ _ \ '__|   \ \/  \/ / _ \ '_ \   \___ \ / __| '__/ _`` | '_ \ / _ \ '__|
        | |\ V  V /| | |_| ||  __/ |       \  /\  /  __/ |_) |  ____) | (__| | | (_| | |_) |  __/ |   
        |_| \_/\_/ |_|\__|\__\___|_|        \/  \/ \___|_.__/  |_____/ \___|_|  \__,_| .__/ \___|_|   
                                                                                     | |              
                                                                                     |_|              
"@
        write-host "`n"
    }
    Function CheckAuthGetUser
    {
        Param(
            [string]$HTMLRESPONSETEXT
        )
        return ([System.Text.RegularExpressions.Regex]::new("\{\`"(.+)\}")).Match(
            @($HTMLRESPONSETEXT.Split("`n")).Where({$_ -match "responsive_web_graphql_verify_credentials_enabled"})
        ).Value | 
        ConvertFrom-Json | 
        % entities | 
        % users | 
        % entities | 
        % (([System.Text.RegularExpressions.Regex]::new("\{\`"(.+)\}")).Match(
            @($HTMLRESPONSETEXT.Split("`n")).Where({$_ -match "responsive_web_graphql_verify_credentials_enabled"})
        ).Value | 
        ConvertFrom-Json | 
        % entities | 
        % users | 
        % entities | 
        gm -MemberType NoteProperty -ea 0| % Name) | % Name
    }
    Function MoveWindowOver
    {
        Param(
            [ValidateSet('LEFT','RIGHT')]
            [string]$SIDE,
            [switch]$THIS_WINDOW,
            [Int32]$PROCESSID
        )
        if(!('NativeMethods.Win32' -as [type])){
            $CS = @"
    using System;
    using System.Runtime.InteropServices;
    namespace NativeMethods
    {
        public class Win32 {
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
        
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);
        
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
        
            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
        }
        public struct RECT
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }
    }
"@
            Add-Type -TypeDefinition $CS -ea 0
        }
        if ($THIS_WINDOW) {
            @(2, 3).ForEach( {
                $null = [NativeMethods.Win32]::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, $_)
            })
            $RECT = New-Object NativeMethods.RECT
            $null = [NativeMethods.Win32]::GetWindowRect((Get-Process -Id $PID -ea 0).MainWindowHandle, [ref]$RECT)
            $WID = ($RECT.Right - $RECT.Left)
            $HIG = $RECT.Bottom - $RECT.Top
            if($SIDE -eq 'LEFT'){
                $NLE = $RECT.Left
            }
            if($SIDE -eq 'RIGHT'){
                $NLE = $RECT.Left + ($WID / 2)
            }
            $NTO = $RECT.Top
            $null = [NativeMethods.Win32]::MoveWindow(
                (Get-Process -Id $PID -ea 0).MainWindowHandle, 
                $NLE, 
                $NTO, 
                ($WID / 2), 
                $HIG,
                $true
            )
        }
        if(!$THIS_WINDOW){
            @(2, 3).ForEach( {
                $null = [NativeMethods.Win32]::ShowWindowAsync((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, $_)
            })
            $RECT = New-Object NativeMethods.RECT
            $null = [NativeMethods.Win32]::GetWindowRect((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, [ref]$RECT)
            $WID = ($RECT.Right - $RECT.Left)
            $HIG = $RECT.Bottom - $RECT.Top
            if($SIDE -eq 'LEFT'){
                $NLE = $RECT.Left
            }
            if($SIDE -eq 'RIGHT'){
                $NLE = $RECT.Left + ($WID / 2)
            }
            $NTO = $RECT.Top
            $null = [NativeMethods.Win32]::MoveWindow(
                (Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, 
                $NLE, 
                $NTO, 
                ($WID / 2), 
                $HIG,
                $true
            )
        }
    }
    
    function WaitFor
    {
    	[cmdletbinding()]
    	param(
    		[Parameter(ValueFromPipeline=$true)]
    		[string]$TITLE,
            [Int32]$PROCESSID
    	)
        $ANIMATION = @()
        $stri = "___________________________________________________________"
        (0..68) | % {
            $ANIMATION += $stri;
            $a = new-object system.collections.arraylist
            $stri.tochararray() | % { $a.add($_) | out-null }
            if($_ -lt 10){
        	    $a[$_] = $a[$_] -replace '_',"#"
        	    $stri = $a -join ''
            }
            if($_ -ge 10 -and $_ -lt 59){
        	    $a[$_] = $a[$_] -replace "_","#"
        	    $a[($_ - 10)] = $a[($_ - 10)] -replace "`#","_"
        	    $stri = $a -join ''
            }
            if($_ -ge 59){
        	    $a[$_ - 10] = $a[$_ - 10] -replace "`#","_"
        	    $stri = $a -join ''
            }
        }
        write-Host "`n"
    	$BLANK = "`b" * ($TITLE.length+60)
    	$CLEAR = " " * ($TITLE.length+60)
    	while(!(Get-Process -Id $PROCESSID -ea 0)){sleep -m 100}
    	while(get-process -Id $PROCESSID -ea 0){
    		$ANIMATION | % {
    			Write-Host "$($BLANK)$($TITLE) $($_)" -NoNewline -ForegroundColor Green
    			Start-Sleep -m 20
    		}
    	}
        Write-Host "$($BLANK)$($CLEAR)$($BLANK)" -NoNewline
        write-Host "`n"
    }
    Function Install_Choco_7z_dotnet_ffmpeg
    {
        Param()
        $command = "RgB1AG4AYwB0AGkAbwBuACAATQBvAHYAZQBXAGkAbgBkAG8AdwBPAHYAZQByAA0ACgB7AA0ACgAgACAAIAAgAFAAYQByAGEAbQAoAA0ACgAgACAAIAAgACAAIAAgACAAWwBWAGEAbABpAGQAYQB0AGUAUwBlAHQAKAAnAEwARQBGAFQAJwAsACcAUgBJAEcASABUACcAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwBzAHQAcgBpAG4AZwBdACQAUwBJAEQARQAsAA0ACgAgACAAIAAgACAAIAAgACAAWwBzAHcAaQB0AGMAaABdACQAVABIAEkAUwBfAFcASQBOAEQATwBXACwADQAKACAAIAAgACAAIAAgACAAIABbAEkAbgB0ADMAMgBdACQAUABSAE8AQwBFAFMAUwBJAEQADQAKACAAIAAgACAAKQANAAoAIAAgACAAIABpAGYAKAAhACgAJwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyACcAIAAtAGEAcwAgAFsAdAB5AHAAZQBdACkAKQB7AA0ACgAgACAAIAAgACAAIAAgACAAJABDAFMAIAA9ACAAQAAiAA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwA7AA0ACgBuAGEAbQBlAHMAcABhAGMAZQAgAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABXAGkAbgAzADIAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACkAXQANAAoAIAAgACAAIAAgACAAIAAgAFsAcgBlAHQAdQByAG4AOgAgAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEIAbwBvAGwAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEcAZQB0AFcAaQBuAGQAbwB3AFIAZQBjAHQAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQALAAgAG8AdQB0ACAAUgBFAEMAVAAgAGwAcABSAGUAYwB0ACkAOwANAAoAIAAgACAAIAANAAoAIAAgACAAIAAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBlAHIAMwAyAC4AZABsAGwAIgApAF0ADQAKACAAIAAgACAAIAAgACAAIABbAHIAZQB0AHUAcgBuADoAIABNAGEAcgBzAGgAYQBsAEEAcwAoAFUAbgBtAGEAbgBhAGcAZQBkAFQAeQBwAGUALgBCAG8AbwBsACkAXQANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABHAGUAdABDAGwAaQBlAG4AdABSAGUAYwB0ACgASQBuAHQAUAB0AHIAIABoAFcAbgBkACwAIABvAHUAdAAgAFIARQBDAFQAIABsAHAAUgBlAGMAdAApADsADQAKACAAIAAgACAADQAKACAAIAAgACAAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwByAGUAdAB1AHIAbgA6ACAATQBhAHIAcwBoAGEAbABBAHMAKABVAG4AbQBhAG4AYQBnAGUAZABUAHkAcABlAC4AQgBvAG8AbAApAF0ADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAATQBvAHYAZQBXAGkAbgBkAG8AdwAoAEkAbgB0AFAAdAByACAAaABXAG4AZAAsACAAaQBuAHQAIABYACwAIABpAG4AdAAgAFkALAAgAGkAbgB0ACAAbgBXAGkAZAB0AGgALAAgAGkAbgB0ACAAbgBIAGUAaQBnAGgAdAAsACAAYgBvAG8AbAAgAGIAUgBlAHAAYQBpAG4AdAApADsADQAKACAAIAAgACAADQAKACAAIAAgACAAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwByAGUAdAB1AHIAbgA6ACAATQBhAHIAcwBoAGEAbABBAHMAKABVAG4AbQBhAG4AYQBnAGUAZABUAHkAcABlAC4AQgBvAG8AbAApAF0ADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAUwBoAG8AdwBXAGkAbgBkAG8AdwBBAHMAeQBuAGMAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQALAAgAGkAbgB0ACAAbgBDAG0AZABTAGgAbwB3ACkAOwANAAoAIAAgACAAIAB9AA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AHIAdQBjAHQAIABSAEUAQwBUAA0ACgAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAGkAbgB0ACAATABlAGYAdAA7ACAAIAAgACAAIAAgACAAIAAvAC8AIAB4ACAAcABvAHMAaQB0AGkAbwBuACAAbwBmACAAdQBwAHAAZQByAC0AbABlAGYAdAAgAGMAbwByAG4AZQByAA0ACgAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABpAG4AdAAgAFQAbwBwADsAIAAgACAAIAAgACAAIAAgACAALwAvACAAeQAgAHAAbwBzAGkAdABpAG8AbgAgAG8AZgAgAHUAcABwAGUAcgAtAGwAZQBmAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAaQBuAHQAIABSAGkAZwBoAHQAOwAgACAAIAAgACAAIAAgAC8ALwAgAHgAIABwAG8AcwBpAHQAaQBvAG4AIABvAGYAIABsAG8AdwBlAHIALQByAGkAZwBoAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAaQBuAHQAIABCAG8AdAB0AG8AbQA7ACAAIAAgACAAIAAgAC8ALwAgAHkAIABwAG8AcwBpAHQAaQBvAG4AIABvAGYAIABsAG8AdwBlAHIALQByAGkAZwBoAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAB9AA0ACgB9AA0ACgAiAEAADQAKACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAFQAeQBwAGUARABlAGYAaQBuAGkAdABpAG8AbgAgACQAQwBTACAALQBlAGEAIAAwAA0ACgAgACAAIAAgAH0ADQAKACAAIAAgACAAaQBmACAAKAAkAFQASABJAFMAXwBXAEkATgBEAE8AVwApACAAewANAAoAIAAgACAAIAAgACAAIAAgAEAAKAAyACwAIAAzACkALgBGAG8AcgBFAGEAYwBoACgAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AFMAaABvAHcAVwBpAG4AZABvAHcAQQBzAHkAbgBjACgAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABJAEQAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgACQAXwApAA0ACgAgACAAIAAgACAAIAAgACAAfQApAA0ACgAgACAAIAAgACAAIAAgACAAJABSAEUAQwBUACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AUgBFAEMAVAANAAoAIAAgACAAIAAgACAAIAAgACQAbgB1AGwAbAAgAD0AIABbAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMALgBXAGkAbgAzADIAXQA6ADoARwBlAHQAVwBpAG4AZABvAHcAUgBlAGMAdAAoACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAFAASQBEACAALQBlAGEAIAAwACkALgBNAGEAaQBuAFcAaQBuAGQAbwB3AEgAYQBuAGQAbABlACwAIABbAHIAZQBmAF0AJABSAEUAQwBUACkADQAKACAAIAAgACAAIAAgACAAIAAkAFcASQBEACAAPQAgACgAJABSAEUAQwBUAC4AUgBpAGcAaAB0ACAALQAgACQAUgBFAEMAVAAuAEwAZQBmAHQAKQANAAoAIAAgACAAIAAgACAAIAAgACQASABJAEcAIAA9ACAAJABSAEUAQwBUAC4AQgBvAHQAdABvAG0AIAAtACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIABpAGYAKAAkAFMASQBEAEUAIAAtAGUAcQAgACcATABFAEYAVAAnACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAEwARQAgAD0AIAAkAFIARQBDAFQALgBMAGUAZgB0AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAUwBJAEQARQAgAC0AZQBxACAAJwBSAEkARwBIAFQAJwApAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQATgBMAEUAIAA9ACAAJABSAEUAQwBUAC4ATABlAGYAdAAgACsAIAAoACQAVwBJAEQAIAAvACAAMgApAA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACQATgBUAE8AIAA9ACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AE0AbwB2AGUAVwBpAG4AZABvAHcAKAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAE4ATABFACwAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAFQATwAsACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACgAJABXAEkARAAgAC8AIAAyACkALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEgASQBHACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAdAByAHUAZQANAAoAIAAgACAAIAAgACAAIAAgACkADQAKACAAIAAgACAAfQANAAoAIAAgACAAIABpAGYAKAAhACQAVABIAEkAUwBfAFcASQBOAEQATwBXACkAewANAAoAIAAgACAAIAAgACAAIAAgAEAAKAAyACwAIAAzACkALgBGAG8AcgBFAGEAYwBoACgAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AFMAaABvAHcAVwBpAG4AZABvAHcAQQBzAHkAbgBjACgAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABSAE8AQwBFAFMAUwBJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgACQAXwApAA0ACgAgACAAIAAgACAAIAAgACAAfQApAA0ACgAgACAAIAAgACAAIAAgACAAJABSAEUAQwBUACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AUgBFAEMAVAANAAoAIAAgACAAIAAgACAAIAAgACQAbgB1AGwAbAAgAD0AIABbAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMALgBXAGkAbgAzADIAXQA6ADoARwBlAHQAVwBpAG4AZABvAHcAUgBlAGMAdAAoACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAFAAUgBPAEMARQBTAFMASQBEACAALQBlAGEAIAAwACkALgBNAGEAaQBuAFcAaQBuAGQAbwB3AEgAYQBuAGQAbABlACwAIABbAHIAZQBmAF0AJABSAEUAQwBUACkADQAKACAAIAAgACAAIAAgACAAIAAkAFcASQBEACAAPQAgACgAJABSAEUAQwBUAC4AUgBpAGcAaAB0ACAALQAgACQAUgBFAEMAVAAuAEwAZQBmAHQAKQANAAoAIAAgACAAIAAgACAAIAAgACQASABJAEcAIAA9ACAAJABSAEUAQwBUAC4AQgBvAHQAdABvAG0AIAAtACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIABpAGYAKAAkAFMASQBEAEUAIAAtAGUAcQAgACcATABFAEYAVAAnACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAEwARQAgAD0AIAAkAFIARQBDAFQALgBMAGUAZgB0AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAUwBJAEQARQAgAC0AZQBxACAAJwBSAEkARwBIAFQAJwApAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQATgBMAEUAIAA9ACAAJABSAEUAQwBUAC4ATABlAGYAdAAgACsAIAAoACQAVwBJAEQAIAAvACAAMgApAA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACQATgBUAE8AIAA9ACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AE0AbwB2AGUAVwBpAG4AZABvAHcAKAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABSAE8AQwBFAFMAUwBJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAE4ATABFACwAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAFQATwAsACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACgAJABXAEkARAAgAC8AIAAyACkALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEgASQBHACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAdAByAHUAZQANAAoAIAAgACAAIAAgACAAIAAgACkADQAKACAAIAAgACAAfQANAAoAfQANAAoATQBvAHYAZQBXAGkAbgBkAG8AdwBPAHYAZQByACAALQBUAEgASQBTAF8AVwBJAE4ARABPAFcAIAAtAFMASQBEAEUAIABMAEUARgBUAA0ACgBpAGYAKAAhACgAZwBlAHQALQBjAG8AbQBtAGEAbgBkACAAYwBoAG8AYwBvACAALQBlAGEAIAAwACkAKQB7AA0ACgAgACAAIAAgAGkAZQB4ACAAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdABdADoAOgBOAGUAdwAoACkAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcABzADoALwAvAGMAaABvAGMAbwBsAGEAdABlAHkALgBvAHIAZwAvAGkAbgBzAHQAYQBsAGwALgBwAHMAMQAiACkADQAKAH0ADQAKACQAUgBFAEcAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBSAGUAZwB1AGwAYQByAEUAeABwAHIAZQBzAHMAaQBvAG4AcwAuAFIAZQBnAGUAeABdADoAOgBuAGUAdwAoACIAXgBkAG8AdABuAGUAdAAoAFwAZAApAFwALgAoAFwAZAApAFsAKABcAHMAKQB8AFwALgBdAFsAKABcAGQAKQB8ACgALgApAF0AIgApAA0ACgBjAGgAbwBjAG8AIABpAG4AcwB0AGEAbABsACAAIgAkACgAQAAoAEAAKABjAGgAbwBjAG8AIABzAGUAYQByAGMAaAAgAGQAbwB0AG4AZQB0ACkALgBXAGgAZQByAGUAKAB7ACQAUgBFAEcALgBNAGEAdABjAGgAKAAiACQAKAAkAF8AKQAiACkALgBTAHUAYwBjAGUAcwBzACAALQBhAG4AZAAgACQAXwAgAC0AbgBvAHQAbQBhAHQAYwBoACAAIgAtACIAIAB9ACkAIAB8ACAAcwBvAHIAdAAgAC0ARABlAHMAYwBlAG4AZABpAG4AZwApAFsAMABdAC4AcwBwAGwAaQB0ACgAJwAgACcAKQBbADAAXQApACIAIAAtAHkADQAKAGkAZgAoACEAKABnAGUAdAAtAGMAbwBtAG0AYQBuAGQAIAA3AHoALgBlAHgAZQAgAC0AZQBhACAAMAApACkAewANAAoAIAAgACAAIABjAGgAbwBjAG8AIABpAG4AcwB0AGEAbABsACAANwB6AGkAcAAgAC0AeQANAAoAfQAgAGUAbABzAGUAIAB7AA0ACgAgACAAIAAgAHcAcgBpAHQAZQAtAGgAbwBzAHQAIAAiADcAegBpAHAAIAAiACAALQBmAG8AcgBlAGcAcgBvAHUAbgBkAGMAbwBsAG8AcgAgAEcAcgBlAGUAbgAgAC0ATgBvAE4AZQB3AEwAaQBuAGUADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAaQBzACAAYQBsAHIAZQBhAGQAeQAgAGkAbgBzAHQAYQBsAGwAZQBkACIAIAAtAGYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAAWQBlAGwAbABvAHcAIAANAAoAfQANAAoAaQBmACgAIQAoAEcAZQB0AC0AQwBvAG0AbQBhAG4AZAAgAGYAZgBtAHAAZQBnAC4AZQB4AGUAIAAtAGUAYQAgADAAKQApAHsADQAKACAAIAAgACAAYwBoAG8AYwBvACAAaQBuAHMAdABhAGwAbAAgAGYAZgBtAHAAZQBnACAALQB5AA0ACgB9ACAAZQBsAHMAZQAgAHsADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAZgBmAG0AcABlAGcAIAAiACAALQBmAG8AcgBlAGcAcgBvAHUAbgBkAGMAbwBsAG8AcgAgAEcAcgBlAGUAbgAgAC0ATgBvAE4AZQB3AEwAaQBuAGUADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAaQBzACAAYQBsAHIAZQBhAGQAeQAgAGkAbgBzAHQAYQBsAGwAZQBkACIAIAAtAGYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAAWQBlAGwAbABvAHcAIAANAAoAfQANAAoADQAKAA=="
        $proc = [System.Diagnostics.Process]::new()
        $si = [System.Diagnostics.ProcessStartInfo]::new()
        $si.FileName = "$($PSHOME)\PowerShell.exe"
        $si.Arguments = " -noprofile -nologo -ep RemoteSigned -ec $($command)"
        $si.Verb = 'RunAs'
        $proc.StartInfo = $si
        $null= $proc.start()
        $PROCESSID = $proc.Id
        sleep -s 2
        "Installing dependencies" | WaitFor -PROCESSID $PROCESSID
    }
    
    Function Get-TWBearerToken
    {
        Param(
            [switch]$SECONDARY
        )
        $CS = @"
    using System.Windows.Forms;
    using System.Drawing;
    namespace Dialog
    {
        public static class Prompt
        {
            public static string ShowDialog(string text, string caption)
            {
                Form prompt = new Form()
                {
                    Width = 500,
                    Height = 150,
                    FormBorderStyle = FormBorderStyle.FixedDialog,
                    Text = caption,
                    StartPosition = FormStartPosition.CenterScreen,
                    Font = new Font("Calibri", 12)
                };
                Label textLabel = new Label() { Left = 50, Top=20, Width = 400, Text=text, Font = new Font("Calibri", 12) };
                TextBox textBox = new TextBox() { Left = 50, Top = 50, Font = new Font("Calibri", 12) };
                textBox.Size = new Size(400,100);
                Button confirmation = new Button() { Text = "Ok", Left = 350, Width = 100, Top = 80, Font = new Font("Calibri", 12), DialogResult = DialogResult.OK };
                confirmation.Click += (sender, e) => { prompt.Close(); };
                prompt.Controls.Add(textBox);
                prompt.Controls.Add(confirmation);
                prompt.Controls.Add(textLabel);
                prompt.AcceptButton = confirmation;
                return prompt.ShowDialog() == DialogResult.OK ? textBox.Text : "";
            }
        }
    }
"@ 
        add-type -typedefinition $CS -ReferencedAssemblies (
            "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
            "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll"
        )
        if($SECONDARY){
            $BEARER = [System.convert]::ToBase64String(
                [System.Security.Cryptography.ProtectedData]::Protect(
                    [System.Text.Encoding]::Unicode.GetBytes(
                        [Dialog.Prompt]::ShowDialog("Please paste your secondary Bearer token and click 'Ok'.","Twitter Scraping Machine")
                    ),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        } else {
            $BEARER = [System.convert]::ToBase64String(
                [System.Security.Cryptography.ProtectedData]::Protect(
                    [System.Text.Encoding]::Unicode.GetBytes(
                        [Dialog.Prompt]::ShowDialog("Please paste your Bearer token and click 'Ok'.","Twitter Scraping Machine")
                    ),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        return $BEARER
    }
    function Install-DotNet_nupkg
    {
        Param(
            [string]$URI
        )
        $H = [ordered]@{
            "Pragma"                    = "no-cache";
            "Cache-Control"             = "no-cache";
            "DNT"                       = "1";
            "Upgrade-Insecure-Requests" = "1";
            "User-Agent"                = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "Sec-Fetch-User"            = "?1";
            "Accept"                    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            "Sec-Fetch-Site"            = "cross-site";
            "Sec-Fetch-Mode"            = "navigate";
            "Referer"                   = "https://www.google.com/";
            "Accept-Encoding"           = "gzip, deflate";
            "Accept-Language"           = "en-US,en;q=0.9";
        }
        $R = Execute-WebRequest -Method GET `
        -HEADERS $H `
        -URI "$($URI)" `
        -NO_COOKIE
        $DLLINK = @(@($R.HtmlDocument.body.getElementsByClassName("list-unstyled ms-Icon-ul")[0]).getElementsByTagName("A")).Where({$_.href.StartsWith("https://www.nuget.org/api/v2")})[0].href
        $FILE = "C:\Temp\$($DLLINK.Split('/')[-2..-1] -join '.').nupkg"
        $FOLDER = "C:\Temp\$($DLLINK.Split('/')[-2..-1] -join '.')\"
        if([System.IO.Directory]::Exists($FOLDER)){
            remove-item $FOLDER -recurse -force -ea 0
        }
        if([System.IO.File]::Exists($FILE)){
            Remove-Item $FILE -ea 0
        }
        $null = [System.IO.Directory]::CreateDirectory($FOLDER)
        ([System.Net.WebClient]::New()).DownloadFile($DLLINK,$FILE)
        $7ZOUT = cmd /c "`"C:\Program Files\7-Zip\7z.exe`" x `"$($FILE)`" -y -o`"$($FOLDER)`" * 2>&1"
        $DLLFILE = @(@(@(gci -Recurse $FOLDER "*$($DLLINK.Split('/')[-2]).dll").Where({
            $_.Directory.Name.Length -le 6 -and `
            $_.Directory.Parent.Name.StartsWith("lib") -and `
            $_.Directory.Parent.Parent.Name.StartsWith("System")
        })) | sort -Property {[int]"$($_.Directory.Name -replace "net")"} -Descending)[0].FullName
        return $DLLFILE
    }
    Function Get-EncryptedCredentialString
    {
        Param()
        $CS = @"
    using System;
    using System.Text;
    using System.Runtime.InteropServices;
    using System.Collections.Generic;
    namespace WinCred
    {
        public class CredentialDialog
        {
            [DllImport("ole32.dll")]
            public static extern void CoTaskMemFree(IntPtr ptr);
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct CREDUI_INFO
            {
                public int cbSize;
                public IntPtr hwndParent;
                public string pszMessageText;
                public string pszCaptionText;
                public IntPtr hbmBanner;
            }
            [DllImport("credui.dll", CharSet = CharSet.Unicode)]
            public static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
                                                                 int authError,
                                                                 ref uint authPackage,
                                                                 IntPtr InAuthBuffer,
                                                                 uint InAuthBufferSize,
                                                                 out IntPtr refOutAuthBuffer,
                                                                 out uint refOutAuthBufferSize,
                                                                 ref bool fSave,
                                                                 int flags);
            [DllImport("credui.dll", CharSet = CharSet.Unicode)]
            public static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
                                                               IntPtr pAuthBuffer,
                                                               uint cbAuthBuffer,
                                                               StringBuilder pszUserName,
                                                               ref int pcchMaxUserName,
                                                               StringBuilder pszDomainName,
                                                               ref int pcchMaxDomainame,
                                                               StringBuilder pszPassword,
                                                               ref int pcchMaxPassword);
            public static List<string> AuthEasy()
            {
                CREDUI_INFO credui = new CREDUI_INFO();
                credui.pszCaptionText = "Enter your network credentials";
                credui.pszMessageText = "Enter your credentials to connect to: Twitter.com";
                credui.cbSize = Marshal.SizeOf(credui);
                uint authPackage = 0;
                IntPtr outCredBuffer = new IntPtr();
                uint outCredSize;
                bool save = false;
    
                int result = CredUIPromptForWindowsCredentials(ref credui, 0, ref authPackage, IntPtr.Zero, 0, out outCredBuffer, out outCredSize, ref save, 1);
    
                var usernameBuf = new StringBuilder(100);
                var passwordBuf = new StringBuilder(100);
                var domainBuf = new StringBuilder(100);
    
                int maxUserName = 100;
                int maxDomain = 100;
                int maxPassword = 100;
                List<string> clis = new List<string>();
                if (result == 0)
                {
                    if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                    {
                        //clear the memory allocated by CredUIPromptForWindowsCredentials
                        CoTaskMemFree(outCredBuffer);
                        
                        clis.Add(usernameBuf.ToString());
                        clis.Add(passwordBuf.ToString());
                        return clis;
                    } else
                    {
                        return clis;
                    }
                } else
                {
                    return clis;
                }
            }
        }
    }
"@
        Add-Type -TypeDefinition $CS 
        $CREDSTR = [System.convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes(
                    "$(@(@([WinCred.CredentialDialog]::AuthEasy()).ForEach({
                        [System.Convert]::ToBase64String(
                            [System.Text.Encoding]::Unicode.GetBytes("$($_)")
                        )
                    })) -join "$([char]167)")"
                ),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        return $CREDSTR
    }
    Function CountDown-Seconds
    {
        Param(
            [int32]$SECONDS
        )
        $SECONDS = "$($SECONDS)"
        $ie = [System.Activator]::createInstance([TYPE]::getTypeFromCLSID([GUID]::parse("{0002DF01-0000-0000-C000-000000000046}")))
        $ie.Navigate("about:blank")
        $ie.Visible = $true; 
        while($ie.busy){ sleep -m 200 }
        $ie.Document.getElementsByTagName("BODY")[0].parentElement.innerHTML = @"
    <!DOCTYPE Html>
    <Html>
        <Head>
            <Meta charset="utf-8"/>
            <Title>Countdown!</TITLE>
            <style>
                body {
                    color: chartreuse;
                    background-color: black;
                    font-family: 'Courier New', Courier, monospace ;
                }
            </style>
        </Head>
        <Body>
            <DIV>
                <H1>TIME SPEAKS</H1>
            </DIV>
            <DIV>
                <H2>MAKE YOUR NEXT API CALL IN ... </H2>
            </DIV>
            <DIV>
                <H3 id="countdown"></H3>
            </DIV>
        </Body>
    </Html>
"@
    $s = @"
    var start = new Date().getTime();
    var end = new Date();
    end.setSeconds(end.getSeconds() + $($SECONDS));
    var done = false;
    var distance = new Date().getTime();
    var str = "MAKE YOUR NEXT API CALL IN ";
    var y = setInterval(function () {
        if ((end.getTime() - new Date().getTime()) <= 0) {
            clearInterval(y);
        }
        if (!(typeof (document.body.getElementsByTagName("h2")[0]) == 'undefined')) {
            if (document.body.getElementsByTagName("h2")[0].innerHTML.split('').filter(function (a) {
                return a.match(new RegExp("\\."));
            }).length < 5) {
                str = "MAKE YOUR NEXT API CALL IN ";
                var li = (document.body.getElementsByTagName("h2")[0].innerHTML.split('').filter(function (a) {
                    return a.match(new RegExp("\\."));
                }).length + 1);
                for (var i = 0; i < li; i++) {
                    str = str + '.';
                }
                document.body.getElementsByTagName("h2")[0].innerHTML = str;
            } else {
                document.body.getElementsByTagName("h2")[0].innerHTML = "MAKE YOUR NEXT API CALL IN ";
            }
        }
    }, 999);
    function stowa() {
        var x = setInterval(function () {
            distance = end.getTime() - new Date().getTime();
            document.getElementById("countdown").innerHTML = Math.floor(distance / (1000 * 60)) + " minutes :: " + Math.floor((distance % (1000 * 60)) / 1000) + " seconds :: " + distance.toString().slice(distance.toString().length - 3, distance.toString().length) + " ms";
            if ((end.getTime() - new Date().getTime()) <= 0) {
                done = true;
                document.getElementById("countdown").parentElement.removeChild(document.getElementById("countdown"));
                document.body.getElementsByTagName("h2")[0].parentElement.removeChild(document.body.getElementsByTagName("h2")[0]);
                clearInterval(x);
            }
        }, 50);
    }
    stowa()
"@
        $sc = $ie.Document.createElement("script")
        $sc.innerHTML = $s
        while($ie.busy){ sleep -m 200 }
        $exec = $ie.Document.getElementsByTagName("BODY")[0].appendChild($sc)
        return $ie
    }
    function Download-Image
    {
        Param(
            [string]$MEDIAURL,
            [string]$TWROOT,
            [string]$LINK,
            [string]$BEARER_TOKEN,
            [string]$CSRF
        )
        $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.convert]::FromBase64String($BEARER_TOKEN),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        $CSRF = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.convert]::FromBase64String($CSRF),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        if($MEDIAURL.Contains("data")){
            $OUTFILE = "$($TWROOT)\IMG\$($LINK.Split('/')[-1])_.$(@($LINK.Split('/')[1]).Split(';')[0])"
            $BYTES = @(); $BYTES += [System.Convert]::FromBase64String("$($MEDIAURL.Split(',')[-1])")
            [System.IO.File]::WriteAllBytes($OUTFILE, $BYTES)
        } else {
            $OUTFILE = "$($TWROOT)\IMG\$($MEDIAURL.Split('/')[4])"
            $WEBCLIENT = [System.Net.WebClient]::new()
            $H = [System.Net.WebHeaderCollection]::new()
            $H.Add("x-csrf-token", "$($CSRF)")
            $H.Add("authority","api.twitter.com")
            $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
            $H.Add("authorization","Bearer $($BEARER_TOKEN)") 
            $WEBCLIENT.Headers = $H
            $WEBCLIENT.Proxy = $null
            $WEBCLIENT.DownloadFile($MEDIAURL,$OUTFILE)
        }
    }
    function Get-TWImages
    {
        Param(
            $WEBRESPONSE
        )
        return $WEBRESPONSE.ResponseText | ConvertFrom-Json | % entities | % media | % media_url_https
    }
    function Download-Video
    {
        Param(
            [string]$VIDEOURL,
            [string]$CSRF,
            [String]$TWROOT,
            [string]$BEARER_TOKEN
        )
        $CSRF = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.convert]::FromBase64String($CSRF),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.convert]::FromBase64String($BEARER_TOKEN),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
        if($VIDEOURL.Contains("mp4")){
            if($STRING){
                (0..$STRING.length).ForEach({ Write-Host "`b" -NoNewline })
            }
            Write-Host "Video found: " -ForegroundColor Red -NoNewline
            Write-Host "$($VIDEOURL)" -ForegroundColor Green
            $WEBCLIENT = [System.Net.WebClient]::new()
            $H = [System.Net.WebHeaderCollection]::new()
            $H.Add("x-csrf-token", "$($CSRF)")
            $H.Add("authority","api.twitter.com")
            $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
            $H.Add("authorization","Bearer $($BEARER_TOKEN)") 
            $WEBCLIENT.Headers = $H
            $FILE = "$($TWROOT)\VID\$(($videoUrl.Split('/')[-1]).split('?')[0])"
            $ENCODED = "$($TWROOT)\VID\ENCODED\$(($VIDEOURL.Split('/')[-1]).split('?')[0])"
            $WEBCLIENT.Proxy = $null
            try {
                $WEBCLIENT.DownloadFile($VIDEOURL,$FILE)
            }
            catch [System.Net.WebException] {
                $EXCEPTION = @(); $_.Exception | % { $EXCEPTION += $_ }
                $NOFFMPEG = $true
                $EXCEPTION.forEach({
                    Write-Host "$($_)" -ForegroundColor Red
                })
            }
            if(!$NOFFMPEG -and !$DONT_REENCODE_VIDEOS){
                $JOB = [System.Diagnostics.Process]::new()
                $SI = [System.Diagnostics.ProcessStartInfo]::new()
                $SI.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
                $SI.fileName = "C:\Windows\system32\cmd.exe"
                $SI.arguments = " /c `"ffmpeg.exe -i `"$($FILE)`" `"$($ENCODED)`" -hide_banner`""
                $JOB.StartInfo = $si
                $null = $JOB.start()
            }
        }
        if($VIDEOURL.Contains("m3u")){
            $WEBCLIENT = [System.Net.WebClient]::new()
            $H = [System.Net.WebHeaderCollection]::new()
            $H.Add("x-csrf-token", "$($CSRF)")
            $H.Add("authority","api.twitter.com")
            $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
            $H.Add("authorization","Bearer $($BEARER_TOKEN)")
            $WEBCLIENT.Headers = $H
            $M3U = $WEBCLIENT.DownloadString($videoUrl)
            $WEBCLIENT.dispose(); remove-variable WEBCLIENT -ea 0
            $WEBCLIENT = [System.Net.WebClient]::new()
            $H = [System.Net.WebHeaderCollection]::new()
            $H.Add("x-csrf-token", "$($CSRF)")
            $H.Add("authority","api.twitter.com")
            $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
            $H.Add("authorization","Bearer $($BEARER_TOKEN)")
            $WEBCLIENT.Headers = $H
            $M3U8 = $WEBCLIENT.DownloadString(
                "https://video.twimg.com$($M3U.split("`n").where({
                    $_ -match "$(($M3U.split("`n").where({$_ -match 'RESOLUTION'}).forEach({
                        @{"$(($_.split('=')[2]).split(',')[0])"= ([int]("$(($_.split('=')[2]).split(',')[0])".split('x')[0]) * [int]("$(($_.split('=')[2]).split(',')[0])".split('x')[1]));}
                    })) | sort values -Descending | select -First 1 | % keys)"
                }) | select -last 1)"
            )
            $VIDBYTES = @();
            $M3U8.Split("`n").where({$_ -match "\.ts$"}).forEach({
                $URL = "https://video.twimg.com$($_)"
                $WEBCLIENT = [System.Net.WebClient]::new()
                $H = [System.Net.WebHeaderCollection]::new()
                $H.Add("x-csrf-token", "$($CSRF)")
                $H.Add("authority","api.twitter.com")
                $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
                $H.Add("authorization","Bearer $($BEARER_TOKEN)")
                $WEBCLIENT.Headers = $H
                $WEBCLIENT.Proxy = $null
                $VIDBYTES += $WEBCLIENT.DownloadData($URL)
                $WEBCLIENT.Dispose(); Remove-Variable wc,url -ea 0
            })
            $FILE = "$($TWROOT)\VID\$(($VIDEOURL.Split('/')[-1]).split('?')[0])" -replace "\.m3u8$",".mp4"
            [System.IO.File]::WriteAllBytes($file,$VIDBYTES)
            if(!$DONT_REENCODE_VIDEOS){
                $ENCODED = "$($TWROOT)\VID\ENCODED\$(($VIDEOURL.Split('/')[-1]).split('?')[0])" -replace "\.m3u8",".mp4"
                $JOB = [System.Diagnostics.Process]::new()
                $SI = [System.Diagnostics.ProcessStartInfo]::new()
                $SI.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
                $SI.fileName = "C:\Windows\system32\cmd.exe"
                $SI.arguments = " /c `"ffmpeg.exe -i `"$($FILE)`" `"$($ENCODED)`" -hide_banner`""
                $JOB.StartInfo = $SI
                $null = $JOB.start()
            }
        }
    }
    function Get-VideoUrl
    {
        Param(
            $WEBRESPONSE
        )
        $URL = $WEBRESPONSE.ResponseText | ConvertFrom-Json | % extended_entities | % media | % video_info | % variants | sort bitrate -Descending | select -First 1 | % url
        if(!$URL){
            $URL = $WEBRESPONSE.ResponseText | ConvertFrom-Json | % track | % playbackurl
        }
        if($URL){
            return $URL
        }
    }
    function Check-RateLimit
    {
        Param(
            $WEBRESPONSE
        )
        if(
            [int32]"$($WEBRESPONSE.HttpResponseHeaders.GetValues("x-rate-limit-remaining"))" -lt 2
        ){
            $IE = CountDown-Seconds -SECONDS (
                [int32]"$($WEBRESPONSE.HttpResponseHeaders.GetValues("x-rate-limit-reset"))" - [math]::round((([datetime]::UtcNow - [datetime]"01-01-1970") | % totalseconds))
            )
            while(
                ([int32]"$($WEBRESPONSE.HttpResponseHeaders.GetValues("x-rate-limit-reset"))" - [math]::round((([datetime]::UtcNow - [datetime]"01-01-1970") | % totalseconds))) -gt 0
            ){
                sleep -s 1
            }
            $IE.quit()
            RelCom($IE)
            Write-Host "`n"
            return $true
        }
    }
    function Get-TWAuthenticityToken
    {
        Param(
            [System.Object[]]$FORMS
        )
        return "$($FORMS | % { $_ | select name,value } | ? {($_ | % Name) -eq 'authenticity_token'} | select -First 1 | % value)"
    }
    function MakeRequestBody
    {
        Param(
            [STRING]$JSON,
            [System.Object[]]$FORMS,
            [string]$ENCRYPTED_CRED_STRING
        )
        $CREDRA = @()
        @("$([System.Text.Encoding]::Unicode.GetString( [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($ENCRYPTED_CRED_STRING),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )))".Split("$([char]167)")).ForEach({
            $CREDRA += [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("$($_)"))
        })
        $JSON = '{ "session%5Busername_or_email%5D": "' + "$($CREDRA[0])" + '", "session%5Bpassword%5D": "' + "$($CREDRA[1])" + '", "authenticity_token": "--MYAUTHTOKEN--", "ui_metrics": "{\"rf\":{\"ad555f04e4ce8d8ea891746a07bfff01728a2a430a7849ea2f48c8aa57359bcd\":-126,\"efc4b66122211ff0147e4b00547e3de404eb77851484f96e82b6605c8ff15b69\":-34,\"c093889af3de9f5e0c95c7c59869c2b1f01edb7f77a1c617466ce170c2fcb897\":-50,\"a8cfc052a2b3a68eadad84d9fe4cef8573e2fb109471909de2cf5076ee631597\":94},\"s\":\"ngvapRO7DD4WJliK96s1FZQut2lYw4wGpaNKrLJLM-agVPat99mFX56X6MV2wUNkhx_-a6skoaeEJSUzAnyWSn7lerF-LeVrHFRkZNzUvfJEZS-eHsFmBXZJEMZhco6B6juM-lVTC_pkfiUuxXljAWvJtpjQFNrd222NGPLxZRJTLzntzUW263derKQmfX_nqI0Xxo0-YZyjQgWhpRrpV6UEg8SM_7EVtC75xLzoDuk79KcW9KTaVRxRX-pfe5kLidkOQqLVEQbAKGIbshpBCeb4T6uRN_lcXT5Wcc61BJPZpUnJHSgFXQgFsIMPJ2TurxnFjubs1USdh0tQiFBgOgAAAWfRqJpX\"}", "scribe_log": "", "redirect_after_login": "", "authenticity_token_": "--MYAUTHTOKEN--", "remember_me": "1"}'
        $OBJ = $JSON -replace '--MYAUTHTOKEN--',"$(Get-TWAuthenticityToken -FORMS $FORMS)" | ConvertFrom-Json
        return "$(@(@(
            'session%5Busername_or_email%5D',
            'session%5Bpassword%5D',
            'authenticity_token',
            'ui_metrics',
            'scribe_log',
            'redirect_after_login',
            'authenticity_token',
            'remember_me'
        ).forEach({
            if($_ -in ("session%5Busername_or_email%5D","session%5Bpassword%5D")){
                "&$($_)=$([uri]::EscapeDataString("$($OBJ | % "$($_)")"))"
            } else {
                "&$([uri]::EscapeDataString("$($_)"))=$([uri]::EscapeDataString("$($OBJ | % "$($_)")"))"
            }
        })) -join '')" -replace "^&",''
    }
    function MakeCookie
    {
        Param(
            [String]$JSON,
            [dateTime]$EXPIRES
        )
        $OBJECT = $JSON | ConvertFrom-JSON
        $cook1 = [System.Net.Cookie]::new()
        $cook1.Name = $OBJECT.Name
        $cook1.Value = $OBJECT.Value
        $cook1.Path = $OBJECT.Path
        $cook1.Domain = $OBJECT.Domain
        if($EXPIRES){
            $cook1.Expires = $EXPIRES
        }
        return $cook1
    }
    function TWLinksFrom-File
    {
        $null = [Microsoft.visualBasic.Interaction]::MsgBox(
            "In the dialog that follows, select the text file containing your list of links to individual tweets.",
            [Microsoft.VisualBasic.MsgBoxStyle]::OkOnly,
            "Twitter Scraping Machine"
        )
        $Open = [System.Windows.Forms.OpenFileDialog]::new()
        $Open.initialDirectory = "$($ENV:USERPROFILE)\DESKTOP"
        $null = $Open.ShowDialog()
        $LinksFile = $Open.filename
        return $LinksFile
    }
    
    function Execute-WebRequest
    {
        Param(
            [ValidateSet('GET','POST')]
            [String]$METHOD,
            [String]$BODY,
            [string]$BEARER,
            [string]$CSRF,
            $HEADERS,
            [String]$URI,
            [System.Net.CookieCollection]$DEFAULTCOOKIES,
            [string]$CONTENT_TYPE,
            [string]$REFERER,
            [switch]$NO_COOKIE,
            [switch]$GET_REDIRECT_URI
        )
        if($CSRF){
            $CSRF = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($CSRF),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        if($BEARER){
            $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($BEARER),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
        Write-Host "HTTP $($METHOD): " -ForegroundColor Yellow -NoNewline
        Write-Host "$($URI.Split('/')[2]) :: " -ForegroundColor Green -NoNewline
        Write-Host "/$($URI.Split('/')[3..($URI.Split('/').length)] -join '/') HTTP/1.1" -ForegroundColor Green
        $HANDLE = [System.Net.Http.HttpClientHandler]::new()
        $HANDLE.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip,[System.Net.DecompressionMethods]::Deflate
        $HANDLE.SslProtocols = (
            [System.Security.Authentication.SslProtocols]::Tls,
            [System.Security.Authentication.SslProtocols]::Tls11,
            [System.Security.Authentication.SslProtocols]::Tls12
        )
        $HANDLE.UseProxy = $false
        $HANDLE.AllowAutoRedirect = $true
        $HANDLE.MaxAutomaticRedirections = 500
        $COOKIE = [System.Net.CookieContainer]::new()
        if($DEFAULTCOOKIES){
            $DEFAULTCOOKIES.ForEach({
                $COOKIE.Add($_)
            })
        }
        $HANDLE.CookieContainer = $COOKIE
        $CLIENT = [System.Net.Http.HttpClient]::new($HANDLE)
        if($BEARER){
            $null = $CLIENT.DefaultRequestHeaders.Add("authorization","Bearer $($BEARER_TOKEN)")
        }
        if($CSRF){
            $null = $CLIENT.DefaultRequestHeaders.Add("x-csrf-token","$($CSRF)")
        }
        if($HEADERS){
            if($HEADERS.gettype() -eq [System.Collections.Specialized.OrderedDictionary]){
                $HEADERS.keys.forEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS["$($_)"])")
                })
            }
            if($HEADERS.gettype() -eq [System.Net.Http.Headers.HttpResponseHeaders]){
                $HEADERS.key.forEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS.getValues("$($_)"))")
                })
            }
        }
        if($CLIENT.DefaultRequestHeaders.Contains("Path")){
            $null = $CLIENT.DefaultRequestHeaders.Remove("Path")
        }
        $null = $CLIENT.DefaultRequestHeaders.Add("Path", "/$($URI.Split('/')[3..($URI.Split('/').length)] -join '/')")
        if($REFERER){
            if($CLIENT.DefaultRequestHeaders.Contains("Referer")){
                $null = $CLIENT.DefaultRequestHeaders.Remove("Referer")
            }
            $null = $CLIENT.DefaultRequestHeaders.Add("Referer",$REFERER)
        }
        if($CONTENT_TYPE){
            $CLIENT.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("$($CONTENT_TYPE)"))
        }
        $OBJ = [psobject]::new()
        switch($METHOD){
            "GET" {
                $RES = $CLIENT.GetAsync($URI)
                $S = $RES.Result.Content.ReadAsStringAsync()
                $HTMLSTRING = $S.Result
                $RESHEAD = $RES.Result.Headers
            }
            "POST" {
                if($CONTENT_TYPE){
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                    $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"$($CONTENT_TYPE)")
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
                if(!$CONTENT_TYPE){
                    if(!$BODY){
                        $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                        $RM.Content = [System.Net.Http.StringContent]::new($null,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                        $RES = $CLIENT.SendAsync($RM)
                        $RESHEAD = $RES.Result.Headers
                        $S = $RES.Result.Content.ReadAsStringAsync()
                        $HTMLSTRING = $S.Result
                    }
                    if($BODY){
                        $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                        $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                        $RES = $CLIENT.SendAsync($RM)
                        $RESHEAD = $RES.Result.Headers
                        $S = $RES.Result.Content.ReadAsStringAsync()
                        $HTMLSTRING = $S.Result
                    }
                }
            }
        }
        if(!$NO_COOKIE){
            $TO = [DateTime]::Now
            while(
                !$HANDLE.CookieContainer.GetCookies($URI) -or `
                (([DateTime]::Now - $TO) | % totalSeconds) -lt 5
            ){ sleep -m 100 }
        }
        $COOKIES = $HANDLE.CookieContainer.GetCookies($URI)
        if($DEFAULTCOOKIES){
            $DEFAULTCOOKIES.ForEach({
                $COOKIES.Add($_)
            })
        }
        if($GET_REDIRECT_URI){
            $TO = [DateTime]::Now
            while(
                !$RES.Result.RequestMessage.RequestUri.AbsoluteUri -or `
                (([DateTime]::Now - $TO) | % totalSeconds) -lt 5
            ){ sleep -m 100 }
            $REDIRECT = $RES.Result.RequestMessage.RequestUri.AbsoluteUri
        }
        if($HTMLSTRING){
            $DOMOBJ = [System.Activator]::createInstance([TYPE]::getTypeFromCLSID([GUID]::Parse("{25336920-03F9-11cf-8FD0-00AA00686F13}")))
            $DOMOBJ.IHTMLDocument2_write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
        }
        if($GET_REDIRECT_URI){
            $OBJ | Add-Member -MemberType NoteProperty -Name RedirectUri -Value $REDIRECT
        }
        $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseMessage -Value $RES
        $OBJ | Add-Member -MemberType NoteProperty -Name CookieCollection -Value $COOKIES
        $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseHeaders -Value $RESHEAD
        if($HTMLSTRING){
            $OBJ | Add-Member -MemberType NoteProperty -Name HtmlDocument -Value $DOMOBJ
            $OBJ | Add-Member -MemberType NoteProperty -Name ResponseText -Value $HTMLSTRING
        }
        return $OBJ
    }
    function CreateDownload-Folders
    {
        Param(
            [string]$LINK
        )
        $ROOTF = "C:\TEMP\SOCIAL\TWITTER\TW_BUCKET\Download\$([dateTime]::Now.ToString('u').split(' ')[0])\$($LINK.split('/')[3])"
        @(
            $ROOTF,
            "$($ROOTF)\VID\",
            "$($ROOTF)\IMG\",
            "$($ROOTF)\VID\ENCODED\"
        ).ForEach({
            if(![System.IO.Directory]::Exists("$($_)")){
                $null = [System.IO.Directory]::CreateDirectory("$($_)")
                Write-Host "Created directory: " -ForegroundColor yellow -NoNewline
                Write-Host "$($_)" -ForegroundColor Green
            } else {
                Write-Host "Directory already exists: " -ForegroundColor Yellow -NoNewline
                Write-Host "$($_)" -ForegroundColor Green
            }
        })
        return $ROOTF
    }
    ########## COMMAND EXECUTION STARTS HERE ##########
    SetConsoleOptions
    Install_Choco_7z_dotnet_ffmpeg 
    AddAllAssemblies
    if($BEARER1){
        $BEARER_TOKEN = [System.convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes($BEARER1),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if($BEARER2){
        $SECONDARY_BEARER = [System.convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes($BEARER2),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if(!$BEARER_TOKEN){
        $BEARER_TOKEN = Get-TWBearerToken
    }
    if(!$SECONDARY_BEARER){
        if(
            "$([Microsoft.VisualBasic.Interaction]::MsgBox(
                "Do you have another Bearer token to add?",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo
            ))" -eq 'Yes'
        ){
            $SECONDARY_BEARER = Get-TWBearerToken -SECONDARY
        }
    }
    $REG = [System.Text.RegularExpressions.Regex]::new("^\{\`"(.+)\}$")
    if(!$links){
        $links = @()
        $links +=[System.IO.File]::ReadAllLines($(TWLinksFrom-File))
    }
    $TWROOT = CreateDownload-Folders -LINK $links[0]
    #### LOGIN AUTH START ####
    while (!$USERNAME) {
        $ECS = Get-EncryptedCredentialString
    
        $CK1 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": "twitter.com", "Expired": false, "Expires": "\/Date(-62135575200000)\/", "Name": "app_shell_visited", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791674)\/", "Value": "1", "Version": 0}'
        $CK2 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": ".twitter.com", "Expired": true, "Expires": "\/Date(1578913611000)\/", "Name": "fm", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791689)\/", "Value": "0", "Version": 0}'
    
        $mediaLink = "https://twitter.com/$($Links[0].Split('/')[3])/media"
        $WebHeaderCollection = @()
        $WebHeaderCollection += [ordered]@{
            "method"                    = "GET"; 
            "authority"                 = "twitter.com"; 
            "scheme"                    = "https"; 
            "path"                      = "/login"; 
            "upgrade-insecure-requests" = "1"; 
            "user-agent"                = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"; 
            "accept"                    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"; 
            "accept-encoding"           = "gzip, deflate"; 
            "accept-language"           = "en-US,en;q=0.9";
        }
        $WebHeaderCollection += [ordered]@{
            "Referer"    = "$($mediaLink)"; 
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        }
        $WebHeaderCollection += [ordered]@{
            "path"                      =	"/sessions";
            "method"                    =	"POST";
            "authority"                 =	"twitter.com";
            "accept"                    =	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            "user-agent"                =	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "scheme"                    =	"https";
            "accept-language"           =	"en-US,en;q=0.9";
            "accept-encoding"           =	"gzip, deflate";
            "upgrade-insecure-requests"	=	"1";
            "Referer"                   =	"$($medialink)";
        }
        $WebHeaderCollection += [ordered]@{
            "path"                      =	"/";
            "method"                    =	"GET";
            "authority"                 =	"twitter.com";
            "accept"                    =	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            "user-agent"                =	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "scheme"                    =	"https";
            "accept-language"           =	"en-US,en;q=0.9";
            "accept-encoding"           =	"gzip, deflate";
            "upgrade-insecure-requests"	=	"1";
            "Referer"                   =	"$($medialink)";
        }
    
        $LOGIN = Execute-WebRequest -METHOD GET `
            -URI "https://twitter.com/login"
        $FORMS = @(); @($LOGIN.HtmlDocument.getElementsByTagName("FORM")).ForEach({ $FORMS += $_ })
    
        $UIMET = Execute-WebRequest -METHOD GET `
            -URI "https://twitter.com/i/js_inst?c_name=ui_metrics"
        $EXPIRES = [DateTime]"$(($UIMET.HttpResponseHeaders.GetValues("Set-Cookie").Split(';') | ? {$_ -match 'expires'} | select -First 1).split('=')[1])"
        $COOKIE1 = MakeCookie -JSON $CK1
        $COOKIE2 = MakeCookie -JSON $CK2 -EXPIRES $EXPIRES
        $BODY = MakeRequestBody -FORMS $FORMS -ENCRYPTED_CRED_STRING $ECS
        $COLLECT = [System.Net.CookieCollection]::new()
        $COLLECT.Add($COOKIE1)
        $COLLECT.Add($COOKIE2)
        $LOGIN.CookieCollection.ForEach( { $COLLECT.Add($_) })
    
        $SESSION = Execute-WebRequest -METHOD POST `
            -BODY $BODY `
            -HEADERS $WebHeaderCollection[2] `
            -URI "https://twitter.com/sessions" `
            -CONTENT_TYPE "application/x-www-form-urlencoded" `
            -DEFAULTCOOKIES $COLLECT
    
        $REDIRECT = Execute-WebRequest -METHOD GET `
            -HEADERS $WebHeaderCollection[3] `
            -DEFAULTCOOKIES $SESSION.CookieCollection `
            -URI 'https://twitter.com'
    
        $USERNAME = CheckAuthGetUser -HTMLRESPONSETEXT $REDIRECT.ResponseText
    
        if(!$USERNAME){
            if(
                ([Microsoft.VisualBasic.Interaction]::MsgBox(
                    "Credentials were invalid!`nTry again?",
                    [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                    "Twitter Scraping Machine"
                )) -eq "No"
            ){
                exit
            }
        }
    }
    #### LOGIN AUTH END ####
    write-host "############################################$(@((0..$USERNAME.length).forEach({ "#" })) -join '')" -ForegroundColor White; 
    write-host "# " -NoNewline -ForegroundColor White
    Write-Host "Login Succeeded! Your Twitter handle is: " -ForegroundColor Yellow -NoNewline
    Write-Host "$($USERNAME)" -ForegroundColor Green -NoNewline
    write-host " #" -ForegroundColor White
    write-host "############################################$(@((0..$USERNAME.length).forEach({ "#" })) -join '')" -ForegroundColor White; 
    
    $CSRF =  [System.Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::Unicode.GetBytes(
                @($REDIRECT.CookieCollection).Where({$_.Name.Contains("ct0")}).Value
            ),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )

    $WebHeaderCollection += [ordered]@{
        "authority"="api.twitter.com";
        "accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
    }
    $WebHeaderCollection += [ordered]@{
        "authority"="api.twitter.com";
        "accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
    }
    
    $ALL = $LINKS.length; $COUNT = 0; $START = [DateTime]::Now; $VidCount = 0; $ImgCount = 0
    forEach($LINK in $LINKS){
        Remove-Variable GETWEET,APICALL,VIDEOURL,RETRY,NOPLAY,MEDIA,TWEETREQ -ea 0
        if([console]::CursorTop -ge 50){ 
            [console]::Clear() 
            @(0..8).ForEach({ Write-Host "`n" })
        }
        $COUNT++
        $GETTWEET = Execute-WebRequest -METHOD GET `
        -BEARER $BEARER_TOKEN `
        -CSRF $CSRF `
        -HEADERS $webheadercollection[5] `
        -NO_COOKIE `
        -URI "https://api.twitter.com/1.1/statuses/show.json?id=$($link.split('/')[-1])&include_entities=true&include_ext_alt_text=true"

        if($GETTWEET.ResponseText.Contains("Rate limit exceeded")){
            $RETRY = $true
        }
        while($RETRY){
            sleep -s 1
            
            
            $GETTWEET = Execute-WebRequest -METHOD GET `
            -BEARER $SECONDARY_BEARER `
            -HEADERS $WebHeaderCollection[4] `
            -CSRF $CSRF `
            -NO_COOKIE `
            -URI "https://api.twitter.com/1.1/statuses/show.json?id=$($link.split('/')[-1])&include_entities=true&include_ext_alt_text=true"
            if($GETTWEET.ResponseText.Contains("Rate limit exceeded")){
                $RETRY = Check-RateLimit -WEBRESPONSE $GETTWEET
            } else {
                remove-variable RETRY -ea 0
            }
        }
        if($REG.Match($GETTWEET.ResponseText).Success){
            $VIDEOURL = Get-VideoUrl -WEBRESPONSE $GETTWEET
        }
        if(!$VIDEOURL -and !$NOAPICALL){
            
            
            $APICALL = Execute-WebRequest -METHOD GET `
            -BEARER $SECONDARY_BEARER `
            -CSRF $CSRF `
            -HEADERS $webheadercollection[4] `
            -NO_COOKIE `
            -URI "https://api.twitter.com/1.1/videos/tweet/config/$($link.Split('/')[-1]).json"
            if($APICALL.ResponseText.Contains("The media could not be played.")){
                $NOPLAY = $true
            }
            if($APICALL.ResponseText.Contains("Rate limit exceeded")){
                $RETRY = $true
            }
            if(!$NOPLAY){
                while($RETRY){
                    sleep -s 1
                    if($APICALL.ResponseText.Contains("Rate limit exceeded")){
                        $RETRY = Check-RateLimit -WEBRESPONSE $APICALL
                    } else {
                        $APICALL = Execute-WebRequest -METHOD GET `
                        -BEARER $SECONDARY_BEARER `
                        -CSRF $CSRF `
                        -HEADERS $webheadercollection[4] `
                        -NO_COOKIE `
                        -URI "https://api.twitter.com/1.1/videos/tweet/config/$($link.Split('/')[-1]).json"
                        remove-variable RETRY -ea 0
                    }
                }
                if($REG.Match($APICALL.ResponseText).Success){
                    $VIDEOURL = Get-VideoUrl -WEBRESPONSE $APICALL
                }
            }
        }
        if($VIDEOURL){
            $vidCount++
            Download-Video -VIDEOURL $VIDEOURL -CSRF $CSRF -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN
        }
        $ELAPSE = ([Datetime]::Now - $START) | % totalseconds
        $REMAIN = ($ELAPSE / ($COUNT / $ALL)) - $ELAPSE
        $END = [Datetime]::Now.addseconds($REMAIN)
        ($END - [dateTime]::Now )| select days, hours, minutes, seconds, milliseconds | % {
            $d = $_ | % days
            $h = $_ | % hours
            $m = $_ | % minutes
            $s = $_ | % seconds
            $ms = $_ | % milliseconds
        }
        $STRING = "$($d) days :: $($h) hours :: $($m) minutes :: $($s) seconds ::$($ms) remaining"
        Write-Progress -PercentComplete ($COUNT/$ALL*100) -Status "$($STRING) :: $([math]::Round(($COUNT/$ALL*100),2))%" -Activity "$($COUNT) of $($ALL) :: Videos: $($vidCount) :: Images: $($ImgCount)"
        if(!$VIDEOURL){
            Write-Host "No videos found in: " -ForegroundColor Red -NoNewline
            Write-Host "$($LINK)" -ForegroundColor Yellow
            $MEDIA = Get-TWImages -WEBRESPONSE $GETTWEET
            if(!$MEDIA){
                
                
                $TWEETREQ = Execute-WebRequest -METHOD GET `
                -BEARER $BEARER_TOKEN `
                -HEADERS $webheadercollection[5] `
                -CSRF $CSRF `
                -NO_COOKIE `
                -URI $LINK
                $MEDIA = @(@($TWEETREQ.HtmlDocument.getElementsByTagName("IMG")).ForEach({ $_ | % src })).Where({
                    $_ -notmatch 'profile' -and `
                    $_ -notmatch 'emoji' -and `
                    $_ -notmatch 'twitter-mobile' -and `
                    $_ -notmatch "^about" -and `
                    $_.length -gt 1
                })
            }
            if($MEDIA){
                Write-Host "Found images in: " -ForegroundColor Red -NoNewline
                write-host "$($LINK)" -ForegroundColor Green
                if(@($MEDIA.split(' ')).Length -gt 1){
                    $C = 0
                    @($MEDIA.split(' ')).ForEach({
                        $ImgCount++
                        Download-Image -MEDIAURL $_ -TWROOT $TWROOT -LINK "$($LINK)_$($c)" -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF
                        $C++
                    })
                } else {
                    if(@("$($MEDIA)".Split(':')).Length -gt 2){
                        $MEDIA = @("$($MEDIA)".Split(':'))[0..("$($MEDIA)".Split(':').Length - 2)] -join ':'
                    }
                    $ImgCount++
                    Download-Image -MEDIAURL $MEDIA -TWROOT $TWROOT -LINK $LINK -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF
                }
            }
            if(!$MEDIA){
                Write-Host "No media available in: " -ForegroundColor Red -NoNewline
                Write-Host "$($LINK)" -ForegroundColor yellow
            }
        }
        $ELAPSE = ([Datetime]::Now - $START) | % totalseconds
        $REMAIN = ($ELAPSE / ($COUNT / $ALL)) - $ELAPSE
        $END = [Datetime]::Now.addseconds($REMAIN)
        ($END - [dateTime]::Now )| select days, hours, minutes, seconds, milliseconds | % {
            $d = $_ | % days
            $h = $_ | % hours
            $m = $_ | % minutes
            $s = $_ | % seconds
            $ms = $_ | % milliseconds
        }
        $STRING = "$($d) days :: $($h) hours :: $($m) minutes :: $($s) seconds ::$($ms) remaining"
        $HOST.UI.RawUI.WindowTitle = "$($STRING) :: $([math]::Round(($COUNT/$ALL*100),2))% :: $($COUNT) of $($ALL)"; 
        Write-Progress -PercentComplete ($COUNT/$ALL*100) -Status "$($STRING) :: $([math]::Round(($COUNT/$ALL*100),2))%" -Activity "$($COUNT) of $($ALL) :: Videos: $($vidCount) :: Images: $($ImgCount)"
    }

    