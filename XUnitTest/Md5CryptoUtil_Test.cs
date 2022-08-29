using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class Md5CryptoUtil_Test
    {
        [Theory]
        [InlineData("cxiaoao", "761E9434DFA78F373655250D4F09707B")]
        [InlineData("123456", "E10ADC3949BA59ABBE56E057F20F883E")]
        [InlineData("张三", "615DB57AA314529AAA0FBE95B3E95BD3")]
        public void Encrypt_Test(string plainText, string answer)
        {
            // arrange


            // act
            string result = Md5CryptoUtil.Encrypt(plainText, Encoding.UTF8);

            // assert
            Assert.Equal(result, answer);
        }
    }
}
