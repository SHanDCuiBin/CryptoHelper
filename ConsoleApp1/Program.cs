// See https://aka.ms/new-console-template for more information
using CryptoHelper;

Console.WriteLine("Hello, World!");

CryptoKey keys = RSACryptoUtil.GeneratePkcs8Keys();

var handle = new RSACryptoUtil(keys.PrivateKey, keys.PublicKey, RSACryptoUtil.Type.Pkcs8);

string value = "hahahaha";

//string jiami = handle.Encrypt(value);
//
////Console.ReadKey();
//
//string jiemi=handle.Decrypt(jiami);


string jiami = handle.PrivateKeyEncrypt(value);

string jiemi=handle.PublicKeyDecrypt(jiami);

Console.ReadKey();