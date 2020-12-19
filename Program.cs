using Jose;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CreateValidateJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            // Work variables
            string iss = "";
            string sub = "";
            string aud = "account-d.docusign.com";
            string privateKey =
                "-----BEGIN RSA PRIVATE KEY-----  UF8UEI/lUUG5TVU=  -----END RSA PRIVATE KEY-----";

            privateKey = privateKey.Replace("  ", "\n");
            byte[] signature = Encoding.UTF8.GetBytes(privateKey); //GetBytesFromPEMFile(Txt_Private_Key.Text, "RSA PRIVATE KEY");
            
            DateTime expiresIn = DateTime.UtcNow.AddDays(30);
            int expireDate = (Int32)(expiresIn.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            var headers = new Dictionary<string, object>()
            {
                { "alg" , "RS256" },
                { "typ" , "JWT" }
            };

            var header = new { alg = "RS256", typ = "JWT" };
            var payload = new Dictionary<string, object>()
            {
            {"iss", iss},
            {"sub", sub},
            {"iat", expireDate.ToString()},
            {"exp", expireDate.ToString()},
            {"aud", aud},
            {"scope", "signature impersonation"}
            };


            // Gera a chave assimetrica
            PemReader pr = new PemReader(new StringReader(privateKey));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);


            // Gera o JWT
            string token = Jose.JWT.Encode(payload, csp, JwsAlgorithm.RS256, extraHeaders: headers);

            Console.WriteLine(token);
        }
    }
}
