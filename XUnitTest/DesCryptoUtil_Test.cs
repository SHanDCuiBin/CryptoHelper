using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class DesCryptoUtil_Test
    {
        [Theory]
        [InlineData("cxiaoao", "GrfZ4PVJYSE=")]
        [InlineData("123456", "HUX+7VtHgb0=")]
        [InlineData("张三", "9HPDBgqSM/4=")]
        public void Encrypt_Test(string plainText, string answer)
        {
            // arrange
            var handle = new DesCryptoUtil("MTIzNDU2Nzg=", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=");

            // act
            string result = handle.Encrypt(plainText);

            // assert
            Assert.Equal(result, answer);
        }

        [Theory]
        [InlineData("GrfZ4PVJYSE=", "cxiaoao")]
        [InlineData("HUX+7VtHgb0=", "123456")]
        [InlineData("9HPDBgqSM/4=", "张三")]
        public void Decrypt_Test(string encrypted, string answer)
        {
            // arrange
            var handle = new DesCryptoUtil("MTIzNDU2Nzg=", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=");

            // act
            string result = handle.Decrypt(encrypted);

            // assert
            Assert.Equal(result, answer);
        }

    }
}
