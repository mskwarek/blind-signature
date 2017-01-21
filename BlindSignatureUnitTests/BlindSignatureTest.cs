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
            BigInteger bs = message.SignBlindedMessage(b);
            s = message.UnblindMessage(bs);
            Assert.IsTrue(message.VerifySignature(s));

            BigInteger check = message.GetMsgFromSignedData(s);

        }

        [TestMethod]
        public void TestNonProperFlow()
        {
            Message message = new Message("1010101");
            BigInteger s = new BigInteger("120321");
            BigInteger b = message.BlindMessage();
            Assert.IsFalse(message.VerifySignature(s));
        }

        [TestMethod]
        public void TestSuccesfulGettingMessageBack()
        {
            Message message = new Message("0101010101010101");
            BigInteger s = null;
            BigInteger b = message.BlindMessage();
            BigInteger bs = message.SignBlindedMessage(b);
            s = message.UnblindMessage(bs);
            BigInteger check = message.GetMsgFromSignedData(s);
            Assert.AreEqual(message.GetRawMessage(), check);
        }
    }
}
