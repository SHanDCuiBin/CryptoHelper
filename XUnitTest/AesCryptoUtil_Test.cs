using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class AesCryptoUtil_Text
    {
        [Theory]
        [InlineData("cxiaoao", "IJZzkfmQeHnfNgKjCtPoOQ==")]
        [InlineData("123456", "94DL2zh97SLRZfhitNGwMA==")]
        [InlineData("张三", "iIyAP6UTi4rnzoBfqZlNLQ==")]
        public void Encrypt_Test(string plainText, string answer)
        {
            // arrange
            string key = Convert.ToBase64String(Encoding.UTF8.GetBytes("lalalalaxididifdjkdfjaklfjdkfd".PadRight(32, '#')));
            string vi = Convert.ToBase64String(Encoding.UTF8.GetBytes("zhangsan".PadRight(16, '#')));
            var handle = new AesCryptoUtil(key, vi, CipherMode.CBC, PaddingMode.PKCS7, Encoding.UTF8);

            // act
            string result = handle.Encrypt(plainText);

            // assert
            Assert.Equal(result, answer);
        }

        [Theory]
        [InlineData("IJZzkfmQeHnfNgKjCtPoOQ==", "cxiaoao")]
        [InlineData("94DL2zh97SLRZfhitNGwMA==", "123456")]
        [InlineData("iIyAP6UTi4rnzoBfqZlNLQ==", "张三")]
        public void Decrypt_Test(string encrypted, string answer)
        {
            // arrange
            string key = Convert.ToBase64String(Encoding.UTF8.GetBytes("lalalalaxididifdjkdfjaklfjdkfd".PadRight(32, '#')));
            string vi = Convert.ToBase64String(Encoding.UTF8.GetBytes("zhangsan".PadRight(16, '#')));
            var handle = new AesCryptoUtil(key, vi, CipherMode.CBC, PaddingMode.PKCS7, Encoding.UTF8);

            // act
            string result = handle.Decrypt(encrypted);

            // assert
            Assert.Equal(result, answer);
        }

    }
}
