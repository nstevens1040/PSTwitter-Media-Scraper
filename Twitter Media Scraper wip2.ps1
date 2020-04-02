
    [cmdletbinding()]
    Param(
        [string]$SECONDARY_BEARER_TOKEN,
        [switch]$DONT_REENCODE_VIDEOS=$true,
        [string]$TARGET_WEBPAGE
    )
    Function Get-EpochUnixTimeUtc
    {
        [cmdletbinding()]
        Param()
        return [math]::Round((([dateTime]::UtcNow - [DateTime]"01-01-1970") |% totalseconds))
    }
    function Cleanup-Links
    {
        Param(
            $PARSED_LINKS
        )
        $r = $false
        if(
            $PARSED_LINKS -ne $null -and `
            $PARSED_LINKS.length -gt 1 -and `
            $GLOBAL:LINKS.IndexOf($PARSED_LINKS) -eq -1
        ){
            if($PARSED_LINKS[1].GetType() -ne [System.Char]){
                if( (@($PARSED_LINKS[1].split("`n")).where({$_.Contains("http")})) ){
                    $GLOBAL:LINKS += @($PARSED_LINKS[1].split("`n")).where({$_.Contains("http")})
                } else {
                    $GLOBAL:LINKS += $PARSED_LINKS
                }
            } else {
                $GLOBAL:LINKS += $PARSED_LINKS
            }
            $r = $true
        }
        return $r
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
        Add-Type -TypeDefinition @"
        using System.Windows.Forms;
        using System.Drawing;
        using System;
        namespace Dialog
        {
            public static class Prompt
            {
                public static string ShowDialog(string text, string caption, string phold = null)
                {
                    int h = Convert.ToInt32(Math.Round(((Graphics.FromImage(new Bitmap(1,1))).MeasureString(text, new Font("Calibri", 12)).Height)));
                    Form prompt = new Form()
                    {
                        Width = 500,
                        Height = 200,
                        FormBorderStyle = FormBorderStyle.FixedDialog,
                        Text = caption,
                        StartPosition = FormStartPosition.CenterScreen,
                        Font = new Font("Calibri", 12)
                    };
                    Label textLabel = new Label() { AutoSize = false, Height = h, Left = 50, Top=20, Width = 400, Text = text, Font = new Font("Calibri", 12) };
                    TextBox textBox = new TextBox() { Size = new Size(400,100), Left = 50, Top = (h + 30), Font = new Font("Calibri", 12) };
                    if(phold != null)
                    {
                        textBox.Text = phold;
                    };
                    Button confirmation = new Button() { Text = "Ok", Left = 350, Width = 100, Top = (h + 60), Font = new Font("Calibri", 12), DialogResult = DialogResult.OK };
                    confirmation.Click += (sender, e) => { prompt.Close(); };
                    prompt.Controls.Add(textBox);
                    prompt.Controls.Add(confirmation);
                    prompt.Controls.Add(textLabel);
                    prompt.AcceptButton = confirmation;
                    return prompt.ShowDialog() == DialogResult.OK ? textBox.Text : "";
                }
            }
        }
"@ `
        -ReferencedAssemblies (
            "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
            "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll",
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
        )
        Add-Type -TypeDefinition @"
        namespace Window.Native
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
        if(!("NativeMethod.Win32" -as [type])){
            Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            namespace NativeMethod
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
        }
            Add-type -TypeDefinition @"
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
        
    }
    Function SetConsoleOptions
    {
        Param()
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
            [Int32]$PROCESSID,
            [Int32]$MAINWINDOWHANDLE
        )
        if ($THIS_WINDOW) {
            @(2, 3).ForEach( {
                $null = [NativeMethod.Win32]::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, $_)
            })
            $RECT = New-Object NativeMethod.RECT
            $null = [NativeMethod.Win32]::GetWindowRect((Get-Process -Id $PID -ea 0).MainWindowHandle, [ref]$RECT)
            $WID = ($RECT.Right - $RECT.Left)
            $HIG = $RECT.Bottom - $RECT.Top
            if($SIDE -eq 'LEFT'){
                $NLE = $RECT.Left
            }
            if($SIDE -eq 'RIGHT'){
                $NLE = $RECT.Left + ($WID / 2)
            }
            $NTO = $RECT.Top
            $null = [NativeMethod.Win32]::MoveWindow(
                (Get-Process -Id $PID -ea 0).MainWindowHandle, 
                $NLE, 
                $NTO, 
                ($WID / 2), 
                $HIG,
                $true
            )
        }
        if(!$THIS_WINDOW){
            if($PROCESSID){
                @(2, 3).ForEach( {
                    $null = [NativeMethod.Win32]::ShowWindowAsync((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, $_)
                })
                $RECT = New-Object NativeMethod.RECT
                $null = [NativeMethod.Win32]::GetWindowRect((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, [ref]$RECT)
                $WID = ($RECT.Right - $RECT.Left)
                $HIG = $RECT.Bottom - $RECT.Top
                if($SIDE -eq 'LEFT'){
                    $NLE = $RECT.Left
                }
                if($SIDE -eq 'RIGHT'){
                    $NLE = $RECT.Left + ($WID / 2)
                }
                $NTO = $RECT.Top
                $null = [NativeMethod.Win32]::MoveWindow(
                    (Get-Process -Id $PROCESSID -ea 0).MainWindowHandle, 
                    $NLE, 
                    $NTO, 
                    ($WID / 2), 
                    $HIG,
                    $true
                )
            }
            if($MAINWINDOWHANDLE){
                @(2, 3).ForEach( {
                    $null = [NativeMethod.Win32]::ShowWindowAsync($MAINWINDOWHANDLE, $_)
                })
                $RECT = New-Object NativeMethod.RECT
                $null = [NativeMethod.Win32]::GetWindowRect($MAINWINDOWHANDLE, [ref]$RECT)
                $WID = ($RECT.Right - $RECT.Left)
                $HIG = $RECT.Bottom - $RECT.Top
                if($SIDE -eq 'LEFT'){
                    $NLE = $RECT.Left
                }
                if($SIDE -eq 'RIGHT'){
                    $NLE = $RECT.Left + ($WID / 2)
                }
                $NTO = $RECT.Top
                $null = [NativeMethod.Win32]::MoveWindow(
                    $MAINWINDOWHANDLE, 
                    $NLE, 
                    $NTO, 
                    ($WID / 2), 
                    $HIG,
                    $true
                )
            }
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
        $TOP = [Console]::CursorTop
        while(!(Get-Process -Id $PROCESSID -ea 0)){sleep -m 100}
        [Console]::CursorVisible = $false
    	while(get-process -Id $PROCESSID -ea 0){
            $ANIMATION.forEach({
                Write-Host $BLANK -NoNewline
                [console]::CursorTop = $top
                [console]::CursorLeft = 0
                Write-Host "$($TITLE) $($_)" -ForegroundColor Green -NoNewline
                sleep -m 20
            })
        }
        Write-Host "$($BLANK)$($CLEAR)$($BLANK)" -NoNewline
        write-Host "`n"
        [Console]::CursorVisible = $true
    }
    Function Install_Choco_7z_dotnet_ffmpeg
    {
        Param()
        $command = "RgB1AG4AYwB0AGkAbwBuACAATQBvAHYAZQBXAGkAbgBkAG8AdwBPAHYAZQByAA0ACgB7AA0ACgAgACAAIAAgAFAAYQByAGEAbQAoAA0ACgAgACAAIAAgACAAIAAgACAAWwBWAGEAbABpAGQAYQB0AGUAUwBlAHQAKAAnAEwARQBGAFQAJwAsACcAUgBJAEcASABUACcAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwBzAHQAcgBpAG4AZwBdACQAUwBJAEQARQAsAA0ACgAgACAAIAAgACAAIAAgACAAWwBzAHcAaQB0AGMAaABdACQAVABIAEkAUwBfAFcASQBOAEQATwBXACwADQAKACAAIAAgACAAIAAgACAAIABbAEkAbgB0ADMAMgBdACQAUABSAE8AQwBFAFMAUwBJAEQADQAKACAAIAAgACAAKQANAAoAIAAgACAAIABpAGYAKAAhACgAJwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyACcAIAAtAGEAcwAgAFsAdAB5AHAAZQBdACkAKQB7AA0ACgAgACAAIAAgACAAIAAgACAAJABDAFMAIAA9ACAAQAAiAA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAFIAdQBuAHQAaQBtAGUALgBJAG4AdABlAHIAbwBwAFMAZQByAHYAaQBjAGUAcwA7AA0ACgBuAGEAbQBlAHMAcABhAGMAZQAgAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABXAGkAbgAzADIAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAdQBzAGUAcgAzADIALgBkAGwAbAAiACkAXQANAAoAIAAgACAAIAAgACAAIAAgAFsAcgBlAHQAdQByAG4AOgAgAE0AYQByAHMAaABhAGwAQQBzACgAVQBuAG0AYQBuAGEAZwBlAGQAVAB5AHAAZQAuAEIAbwBvAGwAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAGUAeAB0AGUAcgBuACAAYgBvAG8AbAAgAEcAZQB0AFcAaQBuAGQAbwB3AFIAZQBjAHQAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQALAAgAG8AdQB0ACAAUgBFAEMAVAAgAGwAcABSAGUAYwB0ACkAOwANAAoAIAAgACAAIAANAAoAIAAgACAAIAAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAHUAcwBlAHIAMwAyAC4AZABsAGwAIgApAF0ADQAKACAAIAAgACAAIAAgACAAIABbAHIAZQB0AHUAcgBuADoAIABNAGEAcgBzAGgAYQBsAEEAcwAoAFUAbgBtAGEAbgBhAGcAZQBkAFQAeQBwAGUALgBCAG8AbwBsACkAXQANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABHAGUAdABDAGwAaQBlAG4AdABSAGUAYwB0ACgASQBuAHQAUAB0AHIAIABoAFcAbgBkACwAIABvAHUAdAAgAFIARQBDAFQAIABsAHAAUgBlAGMAdAApADsADQAKACAAIAAgACAADQAKACAAIAAgACAAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwByAGUAdAB1AHIAbgA6ACAATQBhAHIAcwBoAGEAbABBAHMAKABVAG4AbQBhAG4AYQBnAGUAZABUAHkAcABlAC4AQgBvAG8AbAApAF0ADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAATQBvAHYAZQBXAGkAbgBkAG8AdwAoAEkAbgB0AFAAdAByACAAaABXAG4AZAAsACAAaQBuAHQAIABYACwAIABpAG4AdAAgAFkALAAgAGkAbgB0ACAAbgBXAGkAZAB0AGgALAAgAGkAbgB0ACAAbgBIAGUAaQBnAGgAdAAsACAAYgBvAG8AbAAgAGIAUgBlAHAAYQBpAG4AdAApADsADQAKACAAIAAgACAADQAKACAAIAAgACAAIAAgACAAIABbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgB1AHMAZQByADMAMgAuAGQAbABsACIAKQBdAA0ACgAgACAAIAAgACAAIAAgACAAWwByAGUAdAB1AHIAbgA6ACAATQBhAHIAcwBoAGEAbABBAHMAKABVAG4AbQBhAG4AYQBnAGUAZABUAHkAcABlAC4AQgBvAG8AbAApAF0ADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABiAG8AbwBsACAAUwBoAG8AdwBXAGkAbgBkAG8AdwBBAHMAeQBuAGMAKABJAG4AdABQAHQAcgAgAGgAVwBuAGQALAAgAGkAbgB0ACAAbgBDAG0AZABTAGgAbwB3ACkAOwANAAoAIAAgACAAIAB9AA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AHIAdQBjAHQAIABSAEUAQwBUAA0ACgAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIABwAHUAYgBsAGkAYwAgAGkAbgB0ACAATABlAGYAdAA7ACAAIAAgACAAIAAgACAAIAAvAC8AIAB4ACAAcABvAHMAaQB0AGkAbwBuACAAbwBmACAAdQBwAHAAZQByAC0AbABlAGYAdAAgAGMAbwByAG4AZQByAA0ACgAgACAAIAAgACAAIAAgACAAcAB1AGIAbABpAGMAIABpAG4AdAAgAFQAbwBwADsAIAAgACAAIAAgACAAIAAgACAALwAvACAAeQAgAHAAbwBzAGkAdABpAG8AbgAgAG8AZgAgAHUAcABwAGUAcgAtAGwAZQBmAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAaQBuAHQAIABSAGkAZwBoAHQAOwAgACAAIAAgACAAIAAgAC8ALwAgAHgAIABwAG8AcwBpAHQAaQBvAG4AIABvAGYAIABsAG8AdwBlAHIALQByAGkAZwBoAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAAgACAAIAAgAHAAdQBiAGwAaQBjACAAaQBuAHQAIABCAG8AdAB0AG8AbQA7ACAAIAAgACAAIAAgAC8ALwAgAHkAIABwAG8AcwBpAHQAaQBvAG4AIABvAGYAIABsAG8AdwBlAHIALQByAGkAZwBoAHQAIABjAG8AcgBuAGUAcgANAAoAIAAgACAAIAB9AA0ACgB9AA0ACgAiAEAADQAKACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAFQAeQBwAGUARABlAGYAaQBuAGkAdABpAG8AbgAgACQAQwBTACAALQBlAGEAIAAwAA0ACgAgACAAIAAgAH0ADQAKACAAIAAgACAAaQBmACAAKAAkAFQASABJAFMAXwBXAEkATgBEAE8AVwApACAAewANAAoAIAAgACAAIAAgACAAIAAgAEAAKAAyACwAIAAzACkALgBGAG8AcgBFAGEAYwBoACgAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AFMAaABvAHcAVwBpAG4AZABvAHcAQQBzAHkAbgBjACgAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABJAEQAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgACQAXwApAA0ACgAgACAAIAAgACAAIAAgACAAfQApAA0ACgAgACAAIAAgACAAIAAgACAAJABSAEUAQwBUACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AUgBFAEMAVAANAAoAIAAgACAAIAAgACAAIAAgACQAbgB1AGwAbAAgAD0AIABbAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMALgBXAGkAbgAzADIAXQA6ADoARwBlAHQAVwBpAG4AZABvAHcAUgBlAGMAdAAoACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAFAASQBEACAALQBlAGEAIAAwACkALgBNAGEAaQBuAFcAaQBuAGQAbwB3AEgAYQBuAGQAbABlACwAIABbAHIAZQBmAF0AJABSAEUAQwBUACkADQAKACAAIAAgACAAIAAgACAAIAAkAFcASQBEACAAPQAgACgAJABSAEUAQwBUAC4AUgBpAGcAaAB0ACAALQAgACQAUgBFAEMAVAAuAEwAZQBmAHQAKQANAAoAIAAgACAAIAAgACAAIAAgACQASABJAEcAIAA9ACAAJABSAEUAQwBUAC4AQgBvAHQAdABvAG0AIAAtACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIABpAGYAKAAkAFMASQBEAEUAIAAtAGUAcQAgACcATABFAEYAVAAnACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAEwARQAgAD0AIAAkAFIARQBDAFQALgBMAGUAZgB0AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAUwBJAEQARQAgAC0AZQBxACAAJwBSAEkARwBIAFQAJwApAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQATgBMAEUAIAA9ACAAJABSAEUAQwBUAC4ATABlAGYAdAAgACsAIAAoACQAVwBJAEQAIAAvACAAMgApAA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACQATgBUAE8AIAA9ACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AE0AbwB2AGUAVwBpAG4AZABvAHcAKAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAE4ATABFACwAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAFQATwAsACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACgAJABXAEkARAAgAC8AIAAyACkALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEgASQBHACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAdAByAHUAZQANAAoAIAAgACAAIAAgACAAIAAgACkADQAKACAAIAAgACAAfQANAAoAIAAgACAAIABpAGYAKAAhACQAVABIAEkAUwBfAFcASQBOAEQATwBXACkAewANAAoAIAAgACAAIAAgACAAIAAgAEAAKAAyACwAIAAzACkALgBGAG8AcgBFAGEAYwBoACgAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AFMAaABvAHcAVwBpAG4AZABvAHcAQQBzAHkAbgBjACgAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABSAE8AQwBFAFMAUwBJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgACQAXwApAA0ACgAgACAAIAAgACAAIAAgACAAfQApAA0ACgAgACAAIAAgACAAIAAgACAAJABSAEUAQwBUACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AUgBFAEMAVAANAAoAIAAgACAAIAAgACAAIAAgACQAbgB1AGwAbAAgAD0AIABbAE4AYQB0AGkAdgBlAE0AZQB0AGgAbwBkAHMALgBXAGkAbgAzADIAXQA6ADoARwBlAHQAVwBpAG4AZABvAHcAUgBlAGMAdAAoACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAALQBJAGQAIAAkAFAAUgBPAEMARQBTAFMASQBEACAALQBlAGEAIAAwACkALgBNAGEAaQBuAFcAaQBuAGQAbwB3AEgAYQBuAGQAbABlACwAIABbAHIAZQBmAF0AJABSAEUAQwBUACkADQAKACAAIAAgACAAIAAgACAAIAAkAFcASQBEACAAPQAgACgAJABSAEUAQwBUAC4AUgBpAGcAaAB0ACAALQAgACQAUgBFAEMAVAAuAEwAZQBmAHQAKQANAAoAIAAgACAAIAAgACAAIAAgACQASABJAEcAIAA9ACAAJABSAEUAQwBUAC4AQgBvAHQAdABvAG0AIAAtACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIABpAGYAKAAkAFMASQBEAEUAIAAtAGUAcQAgACcATABFAEYAVAAnACkAewANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAEwARQAgAD0AIAAkAFIARQBDAFQALgBMAGUAZgB0AA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAUwBJAEQARQAgAC0AZQBxACAAJwBSAEkARwBIAFQAJwApAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQATgBMAEUAIAA9ACAAJABSAEUAQwBUAC4ATABlAGYAdAAgACsAIAAoACQAVwBJAEQAIAAvACAAMgApAA0ACgAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACQATgBUAE8AIAA9ACAAJABSAEUAQwBUAC4AVABvAHAADQAKACAAIAAgACAAIAAgACAAIAAkAG4AdQBsAGwAIAA9ACAAWwBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAC4AVwBpAG4AMwAyAF0AOgA6AE0AbwB2AGUAVwBpAG4AZABvAHcAKAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAKABHAGUAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEkAZAAgACQAUABSAE8AQwBFAFMAUwBJAEQAIAAtAGUAYQAgADAAKQAuAE0AYQBpAG4AVwBpAG4AZABvAHcASABhAG4AZABsAGUALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAE4ATABFACwAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABOAFQATwAsACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACgAJABXAEkARAAgAC8AIAAyACkALAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEgASQBHACwADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAdAByAHUAZQANAAoAIAAgACAAIAAgACAAIAAgACkADQAKACAAIAAgACAAfQANAAoAfQANAAoATQBvAHYAZQBXAGkAbgBkAG8AdwBPAHYAZQByACAALQBUAEgASQBTAF8AVwBJAE4ARABPAFcAIAAtAFMASQBEAEUAIABMAEUARgBUAA0ACgBpAGYAKAAhACgAZwBlAHQALQBjAG8AbQBtAGEAbgBkACAAYwBoAG8AYwBvACAALQBlAGEAIAAwACkAKQB7AA0ACgAgACAAIAAgAGkAZQB4ACAAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdABdADoAOgBOAGUAdwAoACkAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACIAaAB0AHQAcABzADoALwAvAGMAaABvAGMAbwBsAGEAdABlAHkALgBvAHIAZwAvAGkAbgBzAHQAYQBsAGwALgBwAHMAMQAiACkADQAKAH0ADQAKACQAUgBFAEcAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBSAGUAZwB1AGwAYQByAEUAeABwAHIAZQBzAHMAaQBvAG4AcwAuAFIAZQBnAGUAeABdADoAOgBuAGUAdwAoACIAXgBkAG8AdABuAGUAdAAoAFwAZAApAFwALgAoAFwAZAApAFsAKABcAHMAKQB8AFwALgBdAFsAKABcAGQAKQB8ACgALgApAF0AIgApAA0ACgBjAGgAbwBjAG8AIABpAG4AcwB0AGEAbABsACAAIgAkACgAQAAoAEAAKABjAGgAbwBjAG8AIABzAGUAYQByAGMAaAAgAGQAbwB0AG4AZQB0ACkALgBXAGgAZQByAGUAKAB7ACQAUgBFAEcALgBNAGEAdABjAGgAKAAiACQAKAAkAF8AKQAiACkALgBTAHUAYwBjAGUAcwBzACAALQBhAG4AZAAgACQAXwAgAC0AbgBvAHQAbQBhAHQAYwBoACAAIgAtACIAIAB9ACkAIAB8ACAAcwBvAHIAdAAgAC0ARABlAHMAYwBlAG4AZABpAG4AZwApAFsAMABdAC4AcwBwAGwAaQB0ACgAJwAgACcAKQBbADAAXQApACIAIAAtAHkADQAKAGkAZgAoACEAKABnAGUAdAAtAGMAbwBtAG0AYQBuAGQAIAA3AHoALgBlAHgAZQAgAC0AZQBhACAAMAApACkAewANAAoAIAAgACAAIABjAGgAbwBjAG8AIABpAG4AcwB0AGEAbABsACAANwB6AGkAcAAgAC0AeQANAAoAfQAgAGUAbABzAGUAIAB7AA0ACgAgACAAIAAgAHcAcgBpAHQAZQAtAGgAbwBzAHQAIAAiADcAegBpAHAAIAAiACAALQBmAG8AcgBlAGcAcgBvAHUAbgBkAGMAbwBsAG8AcgAgAEcAcgBlAGUAbgAgAC0ATgBvAE4AZQB3AEwAaQBuAGUADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAaQBzACAAYQBsAHIAZQBhAGQAeQAgAGkAbgBzAHQAYQBsAGwAZQBkACIAIAAtAGYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAAWQBlAGwAbABvAHcAIAANAAoAfQANAAoAaQBmACgAIQAoAEcAZQB0AC0AQwBvAG0AbQBhAG4AZAAgAGYAZgBtAHAAZQBnAC4AZQB4AGUAIAAtAGUAYQAgADAAKQApAHsADQAKACAAIAAgACAAYwBoAG8AYwBvACAAaQBuAHMAdABhAGwAbAAgAGYAZgBtAHAAZQBnACAALQB5AA0ACgB9ACAAZQBsAHMAZQAgAHsADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAZgBmAG0AcABlAGcAIAAiACAALQBmAG8AcgBlAGcAcgBvAHUAbgBkAGMAbwBsAG8AcgAgAEcAcgBlAGUAbgAgAC0ATgBvAE4AZQB3AEwAaQBuAGUADQAKACAAIAAgACAAdwByAGkAdABlAC0AaABvAHMAdAAgACIAaQBzACAAYQBsAHIAZQBhAGQAeQAgAGkAbgBzAHQAYQBsAGwAZQBkACIAIAAtAGYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAAWQBlAGwAbABvAHcAIAANAAoAfQANAAoADQAKAA=="
        $proc = [System.Diagnostics.Process]@{
            StartInfo = [System.Diagnostics.ProcessStartInfo]@{
                FileName = "$($PSHOME)\PowerShell.exe";
                Arguments = " -noprofile -nologo -ep RemoteSigned -ec $($command)";
                Verb = "RunAs"
            }
        }
        $null= $proc.start()
        $PROCESSID = $proc.Id
        while(!(get-process -Id $PROCESSID -ea 0)){ sleep -m 100}
        "Installing dependencies" | WaitFor -PROCESSID $PROCESSID
    }
    
    Function Get-TWBearerToken
    {
        Param(
            [switch]$SECONDARY
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
            $HEADERS = [ordered]@{
                "method"="GET";
                "authority"="ma-0.twimg.com";
                "scheme"="https";
                "path"="/twitter-assets/responsive-web/web/ltr/main.5b6bf12947d7a3a6.js";
                "pragma"="no-cache";
                "cache-control"="no-cache";
                "dnt"="1";
                "upgrade-insecure-requests"="1";
                "user-agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36";
                "sec-fetch-dest"="document";
                "accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
                "sec-fetch-site"="none";
                "sec-fetch-mode"="navigate";
                "accept-encoding"="gzip, deflate";
                "accept-language"="en-US,en;q=0.9";
            }
            $MAINJS = Execute-WebRequest -METHOD 'GET' `
            -HEADERS $HEADERS `
            -NO_COOKIE `
            -URI "https://ma-0.twimg.com/twitter-assets/responsive-web/web/ltr/main.5b6bf12947d7a3a6.js"
            $BEARER = [System.convert]::ToBase64String(
                [System.Security.Cryptography.ProtectedData]::Protect(
                    [System.Text.Encoding]::Unicode.GetBytes(
                        ([System.Text.RegularExpressions.Regex]::new("BEARER_TOKEN:`"|`"")).Replace(
                            $(([System.Text.RegularExpressions.Regex]::new("BEARER_TOKEN:`"(\w+)%(\w+)`"")).Match($MAINJS.ResponseText).Value),
                            ''
                        )
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
        Write-Host "Image found: " -ForegroundColor Red -NoNewline
        Write-Host "$($MEDIAURL)" -ForegroundColor Green
        if($MEDIAURL.StartsWith("data")){
            $OUTFILE = "$($TWROOT)\IMG\$($LINK.Split('/')[-1])_.$(@($LINK.Split('/')[1]).Split(';')[0])"
            $BYTES = @(); $BYTES += [System.Convert]::FromBase64String("$($MEDIAURL.Split(',')[-1])")
            [System.IO.File]::WriteAllBytes($OUTFILE, $BYTES)
        }
        if($MEDIAURL.Contains("twimg")){
            $OUTFILE = "$($TWROOT)\IMG\$($MEDIAURL.Split('/')[-1])"
            $WEBCLIENT = [System.Net.WebClient]::new()
            $H = [System.Net.WebHeaderCollection]::new()
            $H.Add("x-csrf-token", "$($CSRF)")
            $H.Add("authority","api.twitter.com")
            $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
            $H.Add("authorization","Bearer $($BEARER_TOKEN)") 
            $WEBCLIENT.Headers = $H
            $WEBCLIENT.Proxy = $null
            try {
                $WEBCLIENT.DownloadFile($MEDIAURL,$OUTFILE)
            }
            catch {
                $e = $
                $MEDIAURL | Out-File $EXCEPTIONLOG -Encoding ascii -Append 
                $e.Exception | % { $_ | out-file $EXCEPTIONLOG -Encoding ascii -Append }
            }
        }
        if($MEDIAURL.Contains("twitpic")){
            $R = Execute-WebRequest -METHOD GET `
            -URI "$($MEDIAURL)" `
            -NO_COOKIE
            $URI = $R.HtmlDocument.body.getElementsByTagName("img")[0].src
            $S = Execute-WebRequest -METHOD GET `
            -URI $URI `
            -NO_COOKIE
            $IMG = $S.HttpResponseMessage.Result.Content.ReadAsByteArrayAsync()
            $FILE = "$($TWROOT)\IMG\$("$(@($URI.Split('/')).Where({$_.Contains(".jpg")}))".Split('?')[0])"
            [System.IO.File]::WriteAllBytes($FILE,$IMG.Result)
        }
    }
    function Get-TWImages
    {
        Param(
            $TWEETOBJECT
        )
        $IMGURL = $TWEETOBJECT | % extended_entities | % media | % media_url_https
        if(!$IMGURL){
            $IMGURL = $TWEETOBJECT | % entities | % media | % media_url_https
        }
        if($IMGURL){
            $IMGURL | out-file $DLLINKLOG -encoding Ascii
            return $IMGURL
        }
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
        Write-Host "Video found: " -ForegroundColor Red -NoNewline
        Write-Host "$($VIDEOURL)" -ForegroundColor Green
        if($VIDEOURL.Contains("mp4")){
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
                $e = $_
                $VIDEOURL | out-file $EXCEPTIONLOG -Encoding ascii -Append
                $e.Exception | % { $_ | out-file $EXCEPTIONLOG -Encoding ascii -Append }
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
            $TWEETOBJECT
        )
        $URL = $TWEETOBJECT | % extended_entities | % media | % video_info | % variants | sort bitrate -Descending | select -First 1 | % url
        $MORE = $TWEETOBJECT | % extended_entities | % media | % video_info | % variants | % url
        if(!$URL){
            $URL = $TWEETOBJECT | % track | % playbackurl
        }
        if($URL){
            if($MORE.GetType() -eq [System.Object[]]){
                "##### CHOSE $($URL) #####" | Out-File $DLLINKLOG -Encoding ascii -Append
                $MORE.forEach({
                    "$($_)" | Out-File $DLLINKLOG -Encoding ascii -Append
                })
                "##########`n" | Out-File $DLLINKLOG -Encoding ascii -Append
            } else {
                "##### ONE CHOICE #####" | Out-File $DLLINKLOG -Encoding ascii -Append
                "$($URL)"  | Out-File $DLLINKLOG -Encoding ascii -Append
                "##########" | Out-File $DLLINKLOG -Encoding ascii -Append
            }
            return $URL
        }
    }
    function Get-OtherLinks
    {
        Param(
            $TWEETOBJECT
        )
        $LINKS = @()
        $LINKS += $TWEETOBJECT | % entities | % urls | % expanded_url
        $LINKS += @("$($TWEETOBJECT | % full_text)".Split(' ')).Where({$_.Contains("http")})
        if($LINKS){
            $LINKS.forEach({ $_ | out-file $DLLINKLOG -encoding ascii })
            return $LINKS
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
        return [System.Convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes(
                    "$("$(@(@(
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
                    })) -join '')" -replace "^&",'')"
                ),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
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
    function TW-TargetPage
    {
        $PAGE2SCRAPE = [Dialog.Prompt]::ShowDialog("Enter the Twitter url to the page that you're scraping." + [System.Environment]::NewLine + "It should be formatted like: " + [System.Environment]::NewLine + "    https://twitter.com/screen_name/path","Twitter Scraping Machine","https://twitter.com/")
        return $PAGE2SCRAPE
    }
    
    function Execute-WebRequest
    {
        Param(
            [ValidateSet('GET','POST','HEAD','OPTIONS')]
            [String]$METHOD,
            [String]$BODY,
            [string]$ENCRYPTEDBODY,
            [string]$BEARER,
            [string]$CSRF,
            $HEADERS,
            [String]$URI,
            $DEFAULTCOOKIES,
            [switch]$GOOGLEAPI,
            [string]$CONTENT_TYPE,
            [string]$REFERER,
            [switch]$NO_COOKIE,
            [switch]$GET_REDIRECT_URI
        )
        if($ENCRYPTEDBODY){
            $BODY = [System.Text.Encoding]::Unicode.GetString(
                [System.Security.Cryptography.ProtectedData]::Unprotect(
                    [System.convert]::FromBase64String($ENCRYPTEDBODY),
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::LocalMachine
                )
            )
        }
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
            if($DEFAULTCOOKIES.GETTYPE() -eq [System.Net.CookieCollection]){
                $DEFAULTCOOKIES.ForEach({
                    $COOKIE.Add($_)
                })
            }
            if($DEFAULTCOOKIES.GETTYPE() -eq [System.Collections.hashTable]){
                if($GOOGLEAPI){
                    $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = ".google.com"
                        }
                        $Cookie.Add($cook)
                    })
                }
                if(!$GOOGLEAPI){
                    $DOMAIN = ".$([URI]::New($URI).Host)"
                    $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = $DOMAIN;
                        }
                        $Cookie.Add($cook)
                    })
                }
            }
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
            "HEAD" {
                $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head,"$($URI)")
                $RES = $CLIENT.SendAsync($RM)
                $RESHEAD = $RES.Result.Headers
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
            @($DEFAULTCOOKIES.WHERE({
                $_.value -notin @($COOKIES.forEach({$_.Value}))
            })).forEach({
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
    $epochtime = Get-EpochUnixTimeUtc
    $EXCEPTIONLOG = "C:\TEMP\SOCIAL\TWITTER\TW_BUCKET\Exceptions_$($EpochTime).txt"
    $DLLINKLOG = "C:\TEMP\SOCIAL\TWITTER\TW_BUCKET\Download_Links_$($EpochTime).txt"
    write-host "I'll be logging any exceptions here: " -foregroundcolor Yellow -nonewLine
    write-host $EXCEPTIONLOG -ForegroundColor Green
    write-host "I'll be logging download links here: " -foregroundcolor Yellow -nonewLine
    write-host $DLLINKLOG -ForegroundColor Green
    if($TARGET_WEBPAGE){
        $PAGE2SCRAPE = $TARGET_WEBPAGE
    }
    AddAllAssemblies
    SetConsoleOptions
    Install_Choco_7z_dotnet_ffmpeg 
    if($SECONDARY_BEARER_TOKEN){
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
    if(!$PAGE2SCRAPE){
        $PAGE2SCRAPE = TW-TargetPage
    }
    if(
        $PAGE2SCRAPE -match "^twitter.com" -or `
        $PAGE2SCRAPE -match "^mobile.twitter.com"
    ){
        $PAGE2SCRAPE = "https://$($PAGE2SCRAPE)"
    }
    $MALFORMED = $false
    try {
        $SCRAPEURI = [Uri]::New($PAGE2SCRAPE)
    }
    catch {
        $SCRAPEURI = $false
        $MALFORMED = $true
    }
    if($SCRAPEURI){
        if(
            $SCRAPEURI.scheme -ne 'https' -or `
            $SCRAPEURI.authority -notmatch 'twitter.com' -or `
            $SCRAPEURI.Segments.Length -lt 2

        ){
            $MALFORMED = $true
        }
    }
    while($MALFORMED){
        $null = [Microsoft.VisualBasic.Interaction]::MsgBox(
            "The url $($PAGE2SCRAPE) is not correctly formatted.`nPlease format the url like: https://twitter.com/screen_name/path",
            [Microsoft.VisualBasic.MsgBoxStyle]::Critical,
            "Twitter Scraping Machine"
        )
        $PAGE2SCRAPE = TW-TargetPage
        if(
            $PAGE2SCRAPE -match "^twitter.com" -or `
            $PAGE2SCRAPE -match "^mobile.twitter.com"
        ){$PAGE2SCRAPE = "https://$($PAGE2SCRAPE)"}
        $SCRAPEURI = $false
        try {
            $SCRAPEURI = [Uri]::New($PAGE2SCRAPE)
        }
        catch {
            $SCRAPEURI = $false
            $MALFORMED = $true
        }
        if($SCRAPEURI){
            if(
                $SCRAPEURI.scheme -eq 'https' -and `
                $SCRAPEURI.authority -match 'twitter.com' -or `
                $SCRAPEURI.Segments.Length -ge 2
            ){
                $MALFORMED = $false
            }
        }
    }
    $SCRAPEURI = [Uri]::New($PAGE2SCRAPE)
    $HANDLE = $SCRAPEURI.Segments[1] -replace "/",''

    $USER = Execute-WebRequest -METHOD GET `
    -NO_COOKIE `
    -BEARER $BEARER_TOKEN `
    -URI "https://api.twitter.com/1.1/users/show.json?screen_name=$($HANDLE)"
    
    $uJSON = $USER.ResponseText | ConvertFrom-Json
    $rTWID = $uJSON | % id
    
    $h = [ordered]@{
        "method"="GET";
        "authority"="api.twitter.com";
        "scheme"="https";
        "path"="/2/timeline/media/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=20&ext=mediaStats%2CcameraMoment";
        "pragma"="no-cache";
        "cache-control"="no-cache";
        "dnt"="1";
        "x-twitter-client-language"="en";
        "user-agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
        "sec-fetch-dest"="empty";
        "x-twitter-auth-type"="OAuth2Session";
        "x-twitter-active-user"="yes";
        "accept"="*/*";
        "origin"="https://twitter.com";
        "sec-fetch-site"="same-site";
        "sec-fetch-mode"="cors";
        "referer"="$($PAGE2SCRAPE)";
        "accept-encoding"="gzip, deflate";
        "accept-language"="en-US,en;q=0.9"
    }
    
    #### LOGIN AUTH START ####
    while (!$USERNAME) {
        $ECS = Get-EncryptedCredentialString
    
        $CK1 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": "twitter.com", "Expired": false, "Expires": "\/Date(-62135575200000)\/", "Name": "app_shell_visited", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791674)\/", "Value": "1", "Version": 0}'
        $CK2 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": ".twitter.com", "Expired": true, "Expires": "\/Date(1578913611000)\/", "Name": "fm", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791689)\/", "Value": "0", "Version": 0}'
    
        $mediaLink = "https://twitter.com/$($HANDLE)/media"
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
            -ENCRYPTEDBODY $BODY `
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
    $PAGE2SCRAPE = $PAGE2SCRAPE -replace "/$",''
    if($PAGE2SCRAPE.Contains("likes")){
        $MEDIA_COUNT = $uJSON |% favourites_count
        $URI = "https://api.twitter.com/2/timeline/favorites/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }
    if($PAGE2SCRAPE.Contains("media")){
        $MEDIA_COUNT = $uJSON |% media_count
        $URI = "https://api.twitter.com/2/timeline/media/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }
    if(@($PAGE2SCRAPE.Split('/')).Length -eq 4){
        $MEDIA_COUNT = $uJSON |% statuses_count
        $URI = "https://api.twitter.com/2/timeline/profile/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }


    $h.Remove("path"); $h.Add("path","/$($URI.Split('/')[3..(@($URI.Split('/')).Length)] -join '/')")
    
    $TWEETS = Execute-WebRequest -METHOD GET `
    -BEARER $BEARER_TOKEN `
    -CSRF $CSRF `
    -HEADERS $h `
    -DEFAULTCOOKIES $REDIRECT.CookieCollection `
    -URI $URI
    
    $TWROOT = CreateDownload-Folders -LINK $PAGE2SCRAPE
    $REG = [System.Text.RegularExpressions.Regex]::new("https://twitter.com/(.+)/status/(\d+)/(.+)")
    $GLOBAL:LINKS = @()
    $FINDMEDIA = @()
    $JSON = $TWEETS.ResponseText | convertFrom-JSON
    $TWTS = $JSON | % globalObjects | % tweets

    $JSON | % globalObjects | % tweets | gm -MemberType NoteProperty | % Name | % {
        remove-variable r,ONE,TWO,THR,TID,TWEETOBJECT -ea 0
        $r = $false
        $TID = $_
        $TWEETOBJECT = $TWTS | % $TID
        $ONE = Get-VideoUrl -TWEETOBJECT $TWEETOBJECT
        $TWO = Get-TWImages -TWEETOBJECT $TWEETOBJECT
        $THR = Get-OtherLinks -TWEETOBJECT $TWEETOBJECT
        if($ONE){
            $r = Cleanup-Links -PARSED_LINKS $ONE
        }
        if($TWO){
            $r = Cleanup-Links -PARSED_LINKS $TWO
        }
        if($THR){
            $r = Cleanup-Links -PARSED_LINKS $THR
        }
        if(!$r){ 
            $FINDMEDIA += $TWEETOBJECT 
        }
    }
    $start = Get-Date;
    $c = 0;
    $all = $LINKS.length
    $ex = @()
    $RESOLVE = @()
    $REMOTE = @()
    $GETREDIR = @(
        "https://t.co",
        "http://t.co",
        "http://twitgoo.com",
        "tumblr.com",
        "https://vine.co"
    )
    $LINKS.ForEach({
        remove-variable n,r -ea 0
        $rd = $false
        $n = $_ -replace "\)$",''
        $GETREDIR.ForEach({if($_ -match $n){$rd = $true; continue;}})
        if($rd){
            try {
                $r = Execute-WebRequest -METHOD HEAD -URI $n -NO_COOKIE 
            }
            catch {
                $e = $_
                "HTTP HEAD request failed for $($n)" | out-File $EXCEPTIONLOG -Encoding ascii -Append 
                $e.Exception | % { $_ | out-File $EXCEPTIONLOG -Encoding ascii -Append }
            }
            if($r){ 
                $redi = $r.HttpResponseMessage.Result.RequestMessage.RequestUri.AbsoluteUri
                if($redi -ne $n){
                    if(
                        !$REG.Match($redi).Success -and `
                        $RESOLVE.IndexOf($redi) -eq -1 -and `
                        $redi -notmatch 'video_thumb' -and `
                        $redi -match 'twimg' -or `
                        $redi -match 'twitpic'
                    ){
                        $resolve += $redi
                    }
                } else {
                    if(
                        !$REG.Match($n).Success -and `
                        $RESOLVE.IndexOf($n) -eq -1 -and `
                        $n -notmatch 'video_thumb' -and `
                        $n -match 'twimg' -or `
                        $n -match 'twitpic'
                    ){
                        $resolve += $n
                    }
                }
            }
        } else {
            if(
                !$REG.Match($n).Success -and `
                $RESOLVE.IndexOf($n) -eq -1 -and `
                $n -notmatch 'video_thumb' -and `
                $n -match 'twimg' -or `
                $n -match 'twitpic'
            ){
                $resolve += $n
            } else {
                $REMOTE += $n
            }
        }
        $c++
        $elapsed = ((Get-Date) - $start) | % totalseconds
        $remaining = ($elapsed / ($c / $all)) - $elapsed
        $end = (Get-Date).addseconds($remaining)
        ($end - (Get-Date)) | select days, hours, minutes, seconds, milliseconds | % {
            $days = $_ | % days
            $hours = $_ | % hours
            $minutes = $_ | % minutes
            $seconds = $_ | % seconds
            $ms = $_ | % milliseconds
        }
        $string = "$($days) days :: $($hours) hours :: $($minutes) minutes :: $($seconds) seconds ::$($ms) remaining"
        Write-Progress -PercentComplete ($c/$all*100) -Status "$($string) :: $([math]::Round(($c/$all*100),2))%" -Activity "$($c) of $($all) :: $($n)"
    })
    $START = Get-Date
    $COUNT = 0
    $ALL = $RESOLVE.Count
    $VIDCOUNT = 0
    $IMGCOUNT = 0
    $RESOLVE.forEach({
        $COUNT++
        $uri = $_
        $pre = $_.split('/')[0..2] -join '/'
        try {
            switch($pre){
                "https://pbs.twimg.com" { Download-Image -MEDIAURL $uri -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF; $ImgCount++ }
                "https://video.twimg.com" { Download-Video -VIDEOURL $uri -CSRF $CSRF -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN; $vidCount++ }
                "http://twitpic.com" { Download-Image -MEDIAURL $uri -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF; $ImgCount++ }
            }
        }
        catch {
            $e = $_
            $e.Exception | % { $_ | out-File $EXCEPTIONLOG -Encoding ascii -Append }
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
    })