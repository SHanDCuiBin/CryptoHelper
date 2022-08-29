using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class SHA1CryptoUtil_Test
    {
        [Theory]
        [InlineData("cxiaoao", "3B907DEEA4BD1C998EAE61C7CD8E6BC8BC9AE923")]
        [InlineData("123456", "7C4A8D09CA3762AF61E59520943DC26494F8941B")]
        [InlineData("张三", "CED07FB42B05A2ED9EFA330250E2BB9175F962CE")]
        public void Encrypt_Test(string plainText, string answer)
        {
            // arrange


            // act
            string result = SHA1CryptoUtil.Encrypt(plainText, Encoding.UTF8);

            // assert
            Assert.Equal(result, answer);
        }
    }
}
