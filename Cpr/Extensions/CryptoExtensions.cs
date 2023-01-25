using System.Text;
using Cpr.Services;

namespace Cpr.Extensions
{
    public static class CryptoExtensions
    {
        public static string SvcDecryptWithMasterKey(byte[] cipherText, string key)
        {
            var svc = new AesGcmService(key);

            return svc.Decrypt(cipherText);
        }

        public static string SvcDecryptWithMasterKey(byte[] cipherText, byte[] key)
        {
            var svc = new AesGcmService(Encoding.Default.GetString(key));

            return svc.Decrypt(cipherText);
        }

        public static string SvcDecryptWithMasterKey(string cipherText, string key)
        {
            var svc = new AesGcmService(key);

            return svc.Decrypt(cipherText);
        }

        //public static 
    }
}