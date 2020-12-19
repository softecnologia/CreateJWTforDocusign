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
            string iss = "f6b9d626-80b5-43b5-a437-7849d909941b";
            string sub = "120e5454-2080-48f4-8299-ee45c238020b";
            string aud = "account-d.docusign.com";
            string privateKey =
                "-----BEGIN RSA PRIVATE KEY-----  MIIEogIBAAKCAQEAhv1GeNrKB4D7MMQo1HTGCHrTL+/sJH8V0HrlJfCeJj4X9dWn  LX6YJsITUWgtUJ8lXq45JfTYawlrTHFGjev9zL34B7QBkRXzQuzGXmxS7WFwvxlL  OAUx+eskRzGgEIgGqErfY10KcW3LmGWSCLf6KrR5Tkya7zRyChyEPkL9zb0ngf4e  QhZEw0VhslvOCxz++qNc4nZEcYKDwhxq7woISPfKyJZUEgBQoq6Lk4fqYmZzFDno  7iuauruotf7H4CSI1geF50isLZDqTF90iiU//X4x42AOuLWUkVcLHxL6+MnB8Rod  Lh7bGXa46FrEZoohuL6XbJEMlsw2Ghe302t6lQIDAQABAoIBAANXAebclvIPlWdz  +wSirQGptE7z0zZl9I63c7L4HJmaoLIi6qN8BdyzoZG6j6B2h5Cro9tWDwK69W4r  QVEinSFzM89Q+1bxIZcuz4unh3e7GPSJdix5KG7kC/488pZmHzALxjIpq6f5zPdE  0BOqJaTn2TaAO7ceZ5HrebQmqSvtcAfsRbRpUkMXpYTqc38sZAfU2ORFaNhy82ek  hzd6rO9HntneqCTp2mLVkaP89zM6i7WcTQXo/p0rco2+b/6UGw+Ui99rI3nS/DUV  qOXbpnX4ytCTu4Ji5OrWDy5laxVBb0EHI7JUOK55ORotHqdSF1rvYkDjrGe+wKg3  9i/00zMCgYEA/T+GbHhglY0oo/+jfdwxzEVkGgdatIX3SeFHbjhpMq3842QPF/GN  6bELvY7jsYVDC1+pcfQ8BxLPsNsOEp0kv9ZV7CwXMzROb60+uFi4V6Mls5v5vgv/  /Szdjv/KYY+IURWTNKh7bk79CZi7OvjoyeW3J/t7e2XsWxc5UWLkX38CgYEAiHTI  bd8E6Xtvc6SsaD12GVVa7wDzcVBhpe5ri+h0uJAT6C8BlqiyS64mZoUPE36wKd8I  McrOayJYykbuOSqriPMgH3W5lJu5CnAZ3sQCDW9h67WXZtZ7wokvW69pNFdpnpG8  UJGmbElYhLMhazQz584tD0AnSC9ZhC69f1GAr+sCgYBjE/9bYJ0o5VkJEHK+Qu+Y  o21OYaIzDlZ5KRHxJVDC6x8NN5BQJckHrKSTPNwID8LzKDH6yzrQ6aMn5gvTbHd8  NjbXd0h8V/J37qejJ9K3NrUBV/yVRcyZGHx1/c0H7ke+sVouN9xSg8SrhH17zPYG  R0Eo+1KMLIwT9zoNhUsjsQKBgAJ/oOviGYTs7a2AZmfCOFdeaLvXmJ2Kiz8ujmmR  aBG5EaQ+uBi6Hgmktq9J4GzK9Q7PNqcyv3TWvCl4AwSo81semIf679r4vvqh8tdR  X3g/gdt/B7aqVrnJKUTUgWij8RsmL/yJrjJtZWGIpiQAYLLt44VT92Qq+cih0nZy  V5jhAoGAVnndzCNR1jcpO+0jUHgLLA3WzjQ37AuEZBOEowep4PzmxQNRj5V27tQq  Nh3fUYjYE9su0xacdBnuz1VCgcFKMm97rjzlBZu8PgdYt1CQqjpYxvqDWFXcSJjp  YLgXOOor8ZWpOgfjRMM6q9CEUrkij/d33D60UF8UEI/lUUG5TVU=  -----END RSA PRIVATE KEY-----";

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