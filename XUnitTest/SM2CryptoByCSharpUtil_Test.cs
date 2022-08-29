using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class SM2CryptoByCSharpUtil_Test
    {
        [Fact]
        public void GenerateKeys_Test()
        {
            // arrange

            // act
            var key = SM2CryptoByCSharpUtil.GenerateKeys();

            // assert
            Assert.True(!string.IsNullOrWhiteSpace(key.PrivateKey));
            Assert.True(!string.IsNullOrWhiteSpace(key.PublicKey));
        }

        const string generatePrivateKey = @"00C6210A6F323B173555C629B9DFC9EECA113A9513D0826890D7E03974CC649D07";
        const string generatePublicKey = @"04C7F3967640F9907EEEABF46EB45201B13F9D3DF7351E7223E777CBA9EC9427F771A006CC8C4023C28474E2D08A06BA5439479927F01D4CC33CAD25C84F7F6108";

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        public void EncryptAndDecrypt_Generate_Test(string plainTxt)
        {
            // arrange
            var handle = new SM2CryptoByCSharpUtil(generatePrivateKey, generatePublicKey);

            // act
            var encrypted = handle.Encrypt(plainTxt);
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            // assert
            Assert.Equal(plainTxt, original);
        }

        const string pkcs8PrivateKey = "MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBBIIBVTCCAVECAQEEIL2YKZOxObhwoh3fYUPOohAaXH/9r/U6aQfTL/r2NFy+oIHjMIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD//////////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQGhRANCAATEbEXluwWA6nafwE885s+YRmrA9Kscm7nALwc3HlboJyBibQRqwykVJqKFiGP4YT3RW6vWYyD2LDJkM3acd4Fh";
        const string pkcs8PublicKey = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABMRsReW7BYDqdp/ATzzmz5hGasD0qxybucAvBzceVugnIGJtBGrDKRUmooWIY/hhPdFbq9ZjIPYsMmQzdpx3gWE=";


        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        public void EncryptAndDecrypt_Pkcs8_Test(string plainTxt)
        {
            // arrange
            var handle = new SM2CryptoByCSharpUtil(pkcs8PrivateKey, pkcs8PublicKey, SM2CryptoByCSharpUtil.Type.Pkcs8);

            // act
            var encrypted = handle.Encrypt(plainTxt);
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            // assert
            Assert.Equal(plainTxt, original);
        }
    }
}
