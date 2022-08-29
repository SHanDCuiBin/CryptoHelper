using CryptoHelper;
using System;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class Base64Util_Test
    {
        [Theory]
        [InlineData("cxiaoao", "Y3hpYW9hbw==")]
        [InlineData("123456", "MTIzNDU2")]
        public void Encrypt_Test(string plainText, string answer)
        {
            // arrange

            // act
            string result = Base64CryptoUtil.Encrypt(plainText, Encoding.UTF8);

            // assert
            Assert.Equal(result, answer);
        }

        [Theory]
        [InlineData("Y3hpYW9hbw==", "cxiaoao")]
        [InlineData("MTIzNDU2", "123456")]
        public void Decrypt_Test(string plainText, string answer)
        {
            // arrange

            // act
            string result = Base64CryptoUtil.Decrypt(plainText, Encoding.UTF8);

            // assert
            Assert.Equal(result, answer);
        }
    }
}
