using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace XUnitTest
{
    public class RSACryptoUtil_Test
    {
        [Fact]
        public void GenerateXmlKeys_Test()
        {
            // arrange

            // act
            var key = RSACryptoUtil.GenerateXmlKeys();

            // assert
            Assert.True(key.PrivateKey.IndexOf("<RSAKeyValue>") > -1);
            Assert.True(key.PublicKey.IndexOf("<RSAKeyValue>") > -1);
        }
        
        [Fact]
        public void GeneratePkcs8Keys_Test()
        {
            // arrange

            // act
            var key = RSACryptoUtil.GeneratePkcs8Keys();

            // assert
            Assert.True(key.PrivateKey.IndexOf("BEGIN PRIVATE KEY") > -1 && key.PrivateKey.IndexOf("END PRIVATE KEY") > -1);
            Assert.True(key.PublicKey.IndexOf("BEGIN PUBLIC KEY") > -1 && key.PublicKey.IndexOf("END PUBLIC KEY") > -1);
        }

        const string xmlPrivateKey = "<RSAKeyValue><Modulus>pk7NIMbtDLvKvjR1RF+vSG5JS/dEJI02BWQUkh5rnseNiUbJzUESvzeYiiHIwVP3Q+NMwYsMCOUyNpe9ED6S/dJfTwsCJbk7JrMxo8KAhKfN50VDr7mDlyypjtSehbwMxO76aFJ+yP4y/lbSHLRgW6Ub46OUu+VKnHOzRccgpx0=</Modulus><Exponent>AQAB</Exponent><P>2MEiYxiur39W2zDhkPgoXxIvYX63WMm/Vdln70WfRLu6WYBI7lwTW7gAkrP6aCBWlVrAmvhZiOhZL9wl5vO+xw==</P><Q>xGtlqUneLfQhfy1/Ux4cuxtEYEpWpCOPPR/Mn07ZK37aj/dDAI4Y9zYYdMGaEDqZ4qpMkr6T3lapClNU7MSW+w==</Q><DP>wndUkK/eWdnXZURPu67JGbLJC6GSgXhPz4gENamzIQmEQTRVOnUlcQ5+hSAwMyeARvNrBh52xdwf2E6dOr3IlQ==</DP><DQ>Gp33I863xgBsPaC7vVa6S/yw8l+AiDOtaHoTr47uzP8evR2jvcKDzZROEhxeNU7LpbSwNb6PqTSTKawLOR6W2w==</DQ><InverseQ>FRz8XcZyZBhtD7/6hGXDvgX4Nj1oMIqi2jtSx6xY4m9P2FrUnuIzGRd/KbMKe0n3l9ETH4XUvqMB60Am6cDNZg==</InverseQ><D>IvaaJXPsziqE2ywII1HCdgXJnxDi4JRXcRazRGzkz0LAvMWHE4HEwTKc/R1RKWPPrhQRRPdIlm4o+lU4SDv/hspgXHmXb/l0p3DBKWO9DpNl0iMoGuyc47J74t6qqlTwYWwnMNI2oiFXoKXonDOSKBAYpwmskgbpxYil7nrxyXk=</D></RSAKeyValue>";
        const string  xmlPublicKey = "<RSAKeyValue><Modulus>pk7NIMbtDLvKvjR1RF+vSG5JS/dEJI02BWQUkh5rnseNiUbJzUESvzeYiiHIwVP3Q+NMwYsMCOUyNpe9ED6S/dJfTwsCJbk7JrMxo8KAhKfN50VDr7mDlyypjtSehbwMxO76aFJ+yP4y/lbSHLRgW6Ub46OUu+VKnHOzRccgpx0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}", "pGar9GITRoFHPyEgaP5J5GYgazOlOqzTKiGYjL62y/gYr7eTTw7vWcgJk7Le4JHIZlS7boH89HL8iDtYpvoHZzw2yRRAMh0dh3VRFN38rvvcO38y+Mct7zUZJ/BX5cY3titXa542JHjuu/dbQhePQ3Hd3B6yHpm8xYgLyarIF5M=")]
        public void Sign_Xml_Test(string data, string answer)
        {
            // arrange
            var handle = new RSACryptoUtil(xmlPrivateKey, xmlPublicKey, RSACryptoUtil.Type.Xml);

            // act
            var signature = handle.Sign(data);

            // assert
            Assert.Equal(signature, answer);
        }

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}", "pGar9GITRoFHPyEgaP5J5GYgazOlOqzTKiGYjL62y/gYr7eTTw7vWcgJk7Le4JHIZlS7boH89HL8iDtYpvoHZzw2yRRAMh0dh3VRFN38rvvcO38y+Mct7zUZJ/BX5cY3titXa542JHjuu/dbQhePQ3Hd3B6yHpm8xYgLyarIF5M=")]
        public void Verify_Xml_Test(string data, string signature)
        {
            // arrange
            var handle = new RSACryptoUtil(xmlPrivateKey, xmlPublicKey, RSACryptoUtil.Type.Xml);

            // act
            var r = handle.Verify(data, signature);

            // assert
            Assert.True(r);
        }

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}")]
        public void EncryptAndDecrypt_Xml_Test(string plainText)
        {
            // arrange
            var handle = new RSACryptoUtil(xmlPrivateKey, xmlPublicKey, RSACryptoUtil.Type.Xml);

            // act
            var encrypted = handle.Encrypt(plainText);
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            // assert
            Assert.Equal(plainText, original);
        }



        const string pkcs8PrivateKey = @"-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMelClH8DQoPSqi3
iC5g5NqHZOpXuF5Bg5RvfR0NVL3eOZwnuymC73Ionv9GkhqRDTq2PeQQHW6hw23U
gHiTBvVl6Sp61unIQQBYZ3gukED1zjCzJRCikGO5j7jksCb6rya4tRELPsPMzRns
/Qz3+Y2WwzXqDVOZrv6+txxfDyYFAgMBAAECgYBellj/YtWisIAE03+XyZxj1MYB
KTJWpd97Uh8KxqghlMnirAhGsJxVj91UwNCz+Yk1CebkyKXJJqb6wDVl6vLeNvQ6
wbQDAcECGLY3WvvtH7+X96/aNR4aLiv6aOtyJzwk5iaEugx6tN1yZyAh8BJpaaog
Q2TrY601SvCyeksV+QJBANy0d+cYdJhTio+4UcesxBVoxUj+J58DbIF14wXIkKqX
kr6W7U4Mbf4rfTw36AEOnc+MQd5jfhFPn3OdTICSMk8CQQDnkmCCX8kWgCb3XQxO
OeiWv3zd09pyE9Ko2uPc6RyhiA1SMXENxWHy6DF8wfg6CzHExyvd2IJv4XM+ldne
vTFrAkA4J8b2StenxmHUDZ7pQkEl/WFtIBWutO1Px1H7L7v3W9efnMFGgY0fBau4
vbTPSAvJOjOsRP5Xoz276gMEF66rAkBX1LwIFv51K0wcPE2DihE+xAg/NrA+3mfj
JYqRalUyqyCqURhZKck50XmboRJeKYrJ4OUxcoIenzsPvNRy1/1bAkBSs3OGEW0m
Wiu03ubzl+h7g1KC01Ylu7OGAzR2PbveQE16dJ/XyiVMFayZz8amceO9SpxcHR+c
jHYnxqS8RAi5
-----END PRIVATE KEY-----";
        const string pkcs8PublicKey = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHpQpR/A0KD0qot4guYOTah2Tq
V7heQYOUb30dDVS93jmcJ7spgu9yKJ7/RpIakQ06tj3kEB1uocNt1IB4kwb1Zekq
etbpyEEAWGd4LpBA9c4wsyUQopBjuY+45LAm+q8muLURCz7DzM0Z7P0M9/mNlsM1
6g1Tma7+vrccXw8mBQIDAQAB
-----END PUBLIC KEY-----
";
        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}", "PZVsrEOtXt/1v2tvSE00ZIUFUy1Iz8wuhup7logxFToKeYkGBPA7dkbv02OftaIfQuwK+rPW22UCLxD2cM9y2PRR3KV60vDMmBsGrhtec6hDJJfuG8aIHBuRlyQ0OnN8Ix5ZtcuiWOCFP4c5Hs9aNPF+O2Haiv2REutcKhCTCsc=")]
        public void Sign_Pkcs8_Test(string data, string answer)
        {
            // arrange
            var handle = new RSACryptoUtil(pkcs8PrivateKey, pkcs8PublicKey, RSACryptoUtil.Type.Pkcs8);

            // act
            var signature = handle.Sign(data);

            // assert
            Assert.Equal(signature, answer);
        }

        [Theory]
        [InlineData("{\"name\":\"cxiaoao\"}", "PZVsrEOtXt/1v2tvSE00ZIUFUy1Iz8wuhup7logxFToKeYkGBPA7dkbv02OftaIfQuwK+rPW22UCLxD2cM9y2PRR3KV60vDMmBsGrhtec6hDJJfuG8aIHBuRlyQ0OnN8Ix5ZtcuiWOCFP4c5Hs9aNPF+O2Haiv2REutcKhCTCsc=")]
        public void Verify_Pkcs8_Test(string data, string signature)
        {
            // arrange
            var handle = new RSACryptoUtil(pkcs8PrivateKey, pkcs8PublicKey, RSACryptoUtil.Type.Pkcs8);

            // act
            var r = handle.Verify(data, signature);

            // assert
            Assert.True(r);
        }

        [Theory]
        //[InlineData("{\"name\":\"cxiaoao\"}")]
        [InlineData("{\"name\":\"中华人民共和国\", \"age\": 72, \"birthday\": \"1949-10-01 00:00:00\", \"remark\": \"热烈庆祝中华人民共和国成立72周年，感谢先辈勇往无前，不怕牺牲，是您们为国家和人民争取了72年和平幸福生活。值此佳节，我衷心祝愿伟大祖国繁荣昌盛、风调雨顺！衷心祝愿全国各族人民安居乐业、生活愉快！\"}, \"target\": \"统一台湾，解放日本和韩国。\"， \"jobs\": \"炒房地产，炒金融\", \"foods\": \"中午吃宫爆鸡丁，猪脚饭，真TM的饿死鬼转世。\"")]
        public void EncryptAndDecrypt_Pkcs8_Test(string plainText)
        {
            // arrange
            var handle = new RSACryptoUtil(pkcs8PrivateKey, pkcs8PublicKey, RSACryptoUtil.Type.Pkcs8);

            // act
            var encrypted = handle.Encrypt(plainText);
            Assert.NotEmpty(encrypted);

            var original = handle.Decrypt(encrypted);
            // assert
            Assert.Equal(plainText, original);
        }

        [Theory]
        [InlineData("{\"name\":\"中华人民共和国\", \"age\": 72, \"birthday\": \"1949-10-01 00:00:00\", \"remark\": \"热烈庆祝中华人民共和国成立72周年，感谢先辈勇往无前，不怕牺牲，是您们为国家和人民争取了72年和平幸福生活。值此佳节，我衷心祝愿伟大祖国繁荣昌盛、风调雨顺！衷心祝愿全国各族人民安居乐业、生活愉快！\"}, \"target\": \"统一台湾，解放日本和韩国。\"， \"jobs\": \"炒房地产，炒金融\", \"foods\": \"中午吃宫爆鸡丁，猪脚饭，真TM的饿死鬼转世。\"")]
        public void PrivateKeyEncryptAndPublicKeyDecrypt_Pkcs8_Test(string plainText)
        {
            // arrange
            var handle = new RSACryptoUtil(pkcs8PrivateKey, pkcs8PublicKey, RSACryptoUtil.Type.Pkcs8);

            // act
            var encrypted = handle.PrivateKeyEncrypt(plainText);
            Assert.NotEmpty(encrypted);

            var original = handle.PublicKeyDecrypt(encrypted);
            // assert
            Assert.Equal(plainText, original);
        }

    }
}
