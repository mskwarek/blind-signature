using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using BlindSign;
using Org.BouncyCastle.Math;

namespace BlindSignatureUnitTests
{
    [TestClass]
    public class BlindSignatureTest
    {
        [TestMethod]
        public void TestStandardFlow()
        {
            Message message = new Message("0101010101010101");
            BigInteger s = null;
            BigInteger b = message.BlindMessage();
            Console.WriteLine("\nb = " + b);

            BigInteger bs = message.SignBlindedMessage(b);
            Console.WriteLine("bs = " + bs);

            s = message.UnblindMessage(bs);
            Console.WriteLine("us = " + s);

            Console.WriteLine(message.VerifySignature(s));
            Assert.IsTrue(message.VerifySignature(s));
            Console.WriteLine("s = ", s);
            BigInteger check = message.GetMsgFromSignedData(s);

            //BOTH TESTS RETURN FALSE - s must not be a valid signature of m 

            //byte[] array =	check.ToByteArray();
            //String str = System.Text.Encoding.ASCII.GetString(check.ToByteArray());
            Console.WriteLine(System.Text.Encoding.ASCII.GetString(check.ToByteArray()));
            Console.WriteLine("check = " + check);
        }
    }
}
