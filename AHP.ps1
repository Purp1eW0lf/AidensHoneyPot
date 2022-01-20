<#
Meta:
    Authors:  Umair Qamar (@umairq92) & Dray Agha (@Purp1eW0lf)
    Date: 2021 July 29th
    Purpose: Honeypot box. Will pop up about 'credentials' to waste adversary time.
    Usage: Change registry key HKEY_LOCAL_MACHINE>Software>Microsoft>Windows NT>CurrentVersion>Winlogon. Change from explorer.exe to this script.
#>

# Google Chat webhook
function googlechat_alert{
 # uncomment below and add your google chat webhook
 # TODO : Add more details insied text field, like computer name, IP address

 # $restURI = "https://chat.googleapis.com/v1/"
    $Body = ConvertTo-Json @{
        text = $Adversary_Creds.Password
    }
    try {
        Invoke-RestMethod -uri $restURI -Method Post -body $body -ContentType 'application/json' | Out-Null
    } catch {
        Write-Error (Get-Date) ": Update to GoogleChat went wrong..."
    }
}

#ask Credential
Function cred_snitch {
    
    # GUI to ask adversary for creds
    $Adversary_Creds = (Get-ModernCredential -title "Sign in as Enterprise Admin" -Message "Creds plz Mr Attacker" -username 'Aiden' -ForceUsername).GetNetworkCredential()
    $Date = Get-Date -UFormat "%a %Y-%b-%d %T UTC:%Z" 
    
    sleep 1.5

    #trigger googlechat function
    googlechat_alert
}

Function Get-ModernCredential {
# Code borrowed and ammended from Jordan Borean (@jborean93) <jborean93@gmail.com>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param (
        [Parameter()]
        [String]
        $Message = 'Enter your credentials.',

        [Parameter()]
        [String]
        $Title = 'PowerShell credential request',

        [Parameter()]
        #[AllowEmptyString()]
        [String]
        $Username,

        [Switch]
        $ForceUsername

    )

    begin {
        $addParams = @{}
        $addTypeCommand = Get-Command -Name Add-Type

        # CompilerParameters is used for Windows PowerShell only.
        if ('CompilerParameters' -in $addTypeCommand.Parameters.Keys) {
            $addParams.CompilerParameters = [CodeDom.Compiler.CompilerParameters]@{
                CompilerOptions = '/unsafe'
            }
        }
        else {
            $addParams.CompilerOptions = '/unsafe'
        }

        Add-Type @addParams -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace ModernPrompt
{
    public class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class CREDUI_INFO
        {
            public Int32 cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;

            public CREDUI_INFO()
            {
                this.cbSize = Marshal.SizeOf(this);
            }
        }
    }

    public class NativeMethods
    {
        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredPackAuthenticationBuffer(
            Int32 dwFlags,
            string pszUserName,
            string pszPassword,
            IntPtr pPackedCredentials,
            ref Int32 pcbPackedCredentials);

        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 CredUIPromptForWindowsCredentials(
            NativeHelpers.CREDUI_INFO pUiInfo,
            Int32 dwAuthError,
            ref uint pulAuthPackage,
            IntPtr pvInAuthBuffer,
            uint ulInAuthBufferSize,
            out IntPtr ppvOutAuthBuffer,
            out uint pulOutAuthBufferSize,
            ref bool pfSave,
            Int32 dwFlags);

        [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredUnPackAuthenticationBuffer(
            Int32 dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref Int32 pcchMaxUserName,
            StringBuilder pszDomainName,
            ref Int32 pcchMaxDomainame,
            IntPtr pszPassword,
            ref Int32 pcchMaxPassword);

        [DllImport("Ole32.dll")]
        public static extern void CoTaskMemFree(
            IntPtr pv);

        public static SecureString PtrToSecureStringUni(IntPtr buffer, int length)
        {
            unsafe
            {
                char *charPtr = (char *)buffer.ToPointer();
                return new SecureString(charPtr, length);
            }
        }
    }
}
'@

        $credUI = [ModernPrompt.NativeHelpers+CREDUI_INFO]@{
            pszMessageText = $Message
            pszCaptionText = $Title
        }

        $ERROR_INSUFFICIENT_BUFFER = 0x0000007A
        $ERROR_CANCELLED = 0x00004C7
    }

    end {
        $inCredBufferSize = 0
        $inCredBuffer = [IntPtr]::Zero
        $outCredBufferSize = 0
        $outCredBuffer = [IntPtr]::Zero

        try {
            # If a default username is specified we need to specify an in credential buffer with that name
            if (-not [String]::IsNullOrWhiteSpace($Username)) {
                while ($true) {
                    $res = [ModernPrompt.NativeMethods]::CredPackAuthenticationBuffer(
                        0,
                        $Username,
                        '',
                        $inCredBuffer,
                        [ref]$inCredBufferSize
                    ); $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($res) {
                        break
                    }
                    elseif ($err -eq $ERROR_INSUFFICIENT_BUFFER) {
                        $inCredBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($inCredBufferSize)
                    }
                    else {
                        $exp = [ComponentModel.Win32Exception]$err
                        Write-Error -Message "Failed to pack input username: $($exp.Message)" -Exception $exp
                        return
                    }
                }
            }

            $authPackage = 0
            $save = $false
            $flags = 0

            if ($ForceUsername) {
                $flags = $flags -bor 0x20  # CREDUIWIN_IN_CRED_ONLY
            }

            if ($ShowCurrentUser) {
                $flags = $flags -bor 0x200  # CREDUIWIN_ENUMERATE_CURRENT_USER
            }
    
            $err = [ModernPrompt.NativeMethods]::CredUIPromptForWindowsCredentials(
                $credUI,
                $Win32Error,
                [ref]$authPackage,
                $inCredBuffer,
                $inCredBufferSize,
                [ref]$outCredBuffer,
                [ref]$outCredBufferSize,
                [ref]$save,
                $flags
            )
    
            if ($err -eq $ERROR_CANCELLED) {
                return  # No credential was specified
            }
            elseif ($err) {
                $exp = [ComponentModel.Win32Exception]$err
                Write-Error -Message "Failed to prompt for credential: $($exp.Message)" -Exception $exp
                return
            }

            $usernameLength = 0
            $domainLength = 0
            $passwordLength = 0
            $usernameBuffer = [Text.StringBuilder]::new(0)
            $domainBuffer = [Text.StringBuilder]::new(0)
            $passwordPtr = [IntPtr]::Zero

            try {
                while ($true) {
                    $res = [ModernPrompt.NativeMethods]::CredUnpackAuthenticationBuffer(
                        1,  # CRED_PACK_PROTECTED_CREDENTIALS
                        $outCredBuffer,
                        $outCredBufferSize,
                        $usernameBuffer,
                        [ref]$usernameLength,
                        $domainBuffer,
                        [ref]$domainLength,
                        $passwordPtr,
                        [ref]$passwordLength
                    ); $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
                    if ($res) {
                        break
                    }
                    elseif ($err -eq $ERROR_INSUFFICIENT_BUFFER) {
                        [void]$usernameBuffer.EnsureCapacity($usernameLength)
                        [void]$domainBuffer.EnsureCapacity($passwordLength)
                        $passwordPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($passwordLength)
                    }
                    else {
                        $exp = [ComponentModel.Win32Exception]$err
                        Write-Error -Message "Failed to unpack credential: $($exp.Message)" -Exception $exp
                        return
                    }
                }

                # We want to avoid reading the password as a full string so use this "unsafe" method
                $password = [ModernPrompt.NativeMethods]::PtrToSecureStringUni($passwordPtr, $passwordLength)
            }
            finally {
                if ($passwordPtr -ne [IntPtr]::Zero) {
                    $blanks = [byte[]]::new($passwordLength * 2)  # Char takes 2 bytes
                    [Runtime.InteropServices.Marshal]::Copy($blanks, 0, $passwordPtr, $blanks.Length)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($passwordPtr)
                }
            }

            if ($domainLength) {
                $credUsername = '{0}\{1}' -f ($domainBuffer.ToString(), $usernameBuffer.ToString())
            }
            else {
                $credUsername = $usernameBuffer.ToString()
            }
            [PSCredential]::new($credUsername, $password)
        }
        finally {
            if ($outCredBuffer -ne [IntPtr]::Zero) {
                # Should be calling SecureZeroMemory but we cannot access this in .NET so do the next best thing
                # and wipe the unmanaged memory ourselves.
                $blanks = [byte[]]::new($outCredBufferSize)
                [Runtime.InteropServices.Marshal]::Copy($blanks, 0, $outCredBuffer, $blanks.Length)
                [ModernPrompt.NativeMethods]::CoTaskMemFree($outCredBuffer)
            }

            if ($inCredBuffer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($inCredBuffer)
            }
        }
    }
}

#Execute Script
cred_snitch
