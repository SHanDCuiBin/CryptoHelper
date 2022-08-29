using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public static class ByteUtils
    {
        public static string ToHexString(this byte[] datas)
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < datas.Length; i++)
            {
                builder.Append(string.Format("{0:X2}", datas[i]));
            }
            return builder.ToString().Trim();
        }

        public static byte[] GetBytesByHexString(this string datas)
        {
            var result = new byte[datas.Length / 2];
            for (var x = 0; x < result.Length; x++)
            {
                result[x] = Convert.ToByte(datas.Substring(x * 2, 2), 16);
            }
            return result;
        }
    }
    public class SM2CryptoUtil_Test
    {
        [Fact]
        public void GenerateKeys_Test()
        {
            // arrange

            // act
            string pubkey, privkey;
            SM2CryptoUtil.GenerateKeyHex(out pubkey, out privkey);

            // assert
            Assert.True(!string.IsNullOrWhiteSpace(pubkey));
            Assert.True(!string.IsNullOrWhiteSpace(privkey));
        }

        const string generatePrivateKey = @"00C6210A6F323B173555C629B9DFC9EECA113A9513D0826890D7E03974CC649D07";
        const string generatePublicKey = @"04C7F3967640F9907EEEABF46EB45201B13F9D3DF7351E7223E777CBA9EC9427F771A006CC8C4023C28474E2D08A06BA5439479927F01D4CC33CAD25C84F7F6108";

        [Theory]
        [InlineData("BEmXQZ+0gLJcxDKrGx+8gKYRQ5h/SI6hiZbZ+asr4fyyT8w3sV8Ula6upOa+Mi08jUn9ryioBHz5z503jLXj/0U4HejWLVMwMUU/WwG7+IiJwjt4QErIbvGwBblTvifnKVKopFcqmqOJbSMvsOTOFz26iw==", "{\"name\":\"cxiaoao\"}")]
        public void Decrypt_Generate_Test(string encryptedTxt, string answer)
        {
            // arrange
            var handle = new SM2CryptoUtil(generatePublicKey, generatePrivateKey);
            var encryptedBytes = Convert.FromBase64String(encryptedTxt);

            // act
            var original = handle.Decrypt(encryptedBytes);
            var result = Encoding.UTF8.GetString(original);

            // assert
            Assert.Equal(result, answer);
        }


        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        public void EncryptAndDecrypt_Generate_Test(string plainTxt)
        {
            // arrange
            var handle = new SM2CryptoUtil(generatePublicKey, generatePrivateKey);

            // act
            var encrypted = handle.Encrypt(Encoding.UTF8.GetBytes(plainTxt));
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            var result = Encoding.UTF8.GetString(original);
            // assert
            Assert.Equal(plainTxt, result);
        }

        const string pkcs8PrivateKey = "MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBBIIBVTCCAVECAQEEIL2YKZOxObhwoh3fYUPOohAaXH/9r/U6aQfTL/r2NFy+oIHjMIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD//////////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQGhRANCAATEbEXluwWA6nafwE885s+YRmrA9Kscm7nALwc3HlboJyBibQRqwykVJqKFiGP4YT3RW6vWYyD2LDJkM3acd4Fh";
        const string pkcs8PublicKey = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABMRsReW7BYDqdp/ATzzmz5hGasD0qxybucAvBzceVugnIGJtBGrDKRUmooWIY/hhPdFbq9ZjIPYsMmQzdpx3gWE=";
        const string id = "Q3hpYW9hbzEyMzQ1NkFiY2NjKmRmMjNkZ3U5dWptLA==";



        [Theory]
        [InlineData("BFtvD/VC1MfkSsRGaoxqt/T09kAXHXYJLS6GZ6XwSf6qhjelNrk/MImw1r+9eh/cIrRSdIslw/49WlG6kntJTXGWUzb5Xfd5SpOOAamHBZMjnjFs465VlyrMXDm6zZA4K3LDmGDlVx4+94NvKd1Il5nHVg==", "{\"name\":\"cxiaoao\"}")]
        [InlineData("BMML4aCRr5gMJwlwTiDxxaE0y9TwlXlCFqO+p/kyN0zFGjUZnesdxspXGkRs3fE8fEYoORsMNa6C4ldYPZCUaCRs5TdrJhRh6go8WgxP0DT/rZ/powFauZcyMYOWX4k9ncaZFr/H8Svo7w==", "1Q2w3e%^&")]
        [InlineData("BKuvAFRyCi+Q2MNtZeL2iPfgfRFBhNHCagQpPq9RzYRdF21LQq/dTCOwtHrOzYS2tCGPzlYciNHS4UD5ICwM2XAERWwC1FjxiBmwc4vbB0+ILBLyJ+NYHrxG9+GvE4C42aA1zKTYkXoeMTRegKPzd6dLw8+dqt6lo0P7neMprV53O1pLml3ORDNWcUwCkac9RIm50ijI", "{\"Name\": \"Cxiaoao\", \"Age\": 454, \"Other\": \"1Q2w3e%^&\"}")]
        public void Decrypt_Pkcs8_Test(string encryptedTxt, string answer)
        {
            // arrange
            var handle = new SM2CryptoUtil(pkcs8PublicKey, pkcs8PrivateKey, SM2CryptoUtil.Mode.C1C2C3, true);
            var encryptedBytes = Convert.FromBase64String(encryptedTxt);

            // act
            var original = handle.Decrypt(encryptedBytes);
            var result = Encoding.UTF8.GetString(original);

            // assert
            Assert.Equal(result, answer);
        }



        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        [InlineData("1Q2w3e%^&")]
        [InlineData("{\"Name\": \"Cxiaoao\", \"Age\": 454, \"Other\": \"1Q2w3e%^&\"}")]
        public void EncryptAndDecrypt_Pkcs8_Test(string plainTxt)
        {
            // arrange
            var handle = new SM2CryptoUtil(pkcs8PublicKey, pkcs8PrivateKey, SM2CryptoUtil.Mode.C1C2C3, true);

            // act
            var encrypted = handle.Encrypt(Encoding.UTF8.GetBytes(plainTxt));
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            var originalResult = Encoding.UTF8.GetString(original);
            // assert
            Assert.Equal(plainTxt, originalResult);
        }

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        [InlineData("1Q2w3e%^&")]
        [InlineData("{\"Name\": \"Cxiaoao\", \"Age\": 454, \"Other\": \"1Q2w3e%^&\"}")]
        public void SignAndVerifySign_Pkcs8_Test(string plainTxt)
        {
            // arrange
            var handle = new SM2CryptoUtil(pkcs8PublicKey, pkcs8PrivateKey, SM2CryptoUtil.Mode.C1C2C3, true);
            var plainBytes = Encoding.UTF8.GetBytes(plainTxt);
            var idBytes = Encoding.UTF8.GetBytes(id);

            // act
            var signBytes = handle.Sign(plainBytes, idBytes);
            Assert.NotEmpty(signBytes);

            var verifySingResult = handle.VerifySign(plainBytes, signBytes, idBytes);

            // assert
            Assert.True(verifySingResult);
        }
    }
}
