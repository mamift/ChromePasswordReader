using ChromePasswordReader;
using NUnit.Framework;
using System.Collections.Generic;
using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using ChromeWork;

namespace CprTests
{
    public class GetLoginDataTests
    {
        private string _localApplicationData;

        [SetUp]
        public void Setup()
        {
            _localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        [Test]
        public void Chrome()
        {
            string googleChromeUserData = _localApplicationData + @"\Google\Chrome\User Data";
            
            List<string> chromeLoginDataFiles = new List<string> {
                googleChromeUserData + @"\Default\Login Data",
                googleChromeUserData + @"\Login Data"
            };

            Utility.GetLoginData(googleChromeUserData, chromeLoginDataFiles);
        }

        [Test]
        public void Chrome2()
        {
            string googleChromeUserData = _localApplicationData + @"\Google\Chrome\User Data";

            var defaultProfileLoginData = googleChromeUserData + @"\Default\Login Data";

            var w = new Work();
            var enumerable = w.GetPasswords(defaultProfileLoginData).ToList();
        }

        [Test]
        public void Edge()
        {
            string edgeiumUserData = _localApplicationData + @"\Microsoft\Edge\User Data";
            
            List<string> edgiumLoginDataFiles = new List<string> {
                edgeiumUserData + @"\Default\Login Data",
                edgeiumUserData + @"\Login Data"
            };

            Utility.GetLoginData(edgeiumUserData, edgiumLoginDataFiles);
        }
    }
}