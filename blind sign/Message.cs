using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;

namespace BlindSign
{
    public class Message
    {
        public Message(string msg)
        {
            AsymmetricCipherKeyPair keyPair = this.GenerateKeyPair(1024);
            this.PrivateKey = (RsaKeyParameters)keyPair.Private;
            this.PublicKey = (RsaKeyParameters)keyPair.Public;
            this.message = msg;
            this.randomBigInt = this.GenerateRandomRelativelyPrimeBigInteger();
        }

        public String message
        {
            get;
        }

        public RsaKeyParameters PublicKey
        {
            get;
        }

        public BigInteger GetRawMessage()
        {
            return new BigInteger(Encoding.ASCII.GetBytes(message));
        }

        public BigInteger BlindMessage()
        {
            return this.randomBigInt.ModPow(this.GetEFactor(), this.GetNFactor()).Multiply(this.GetRawMessage()).Mod(this.GetNFactor());
        }

        public BigInteger SignBlindedMessage(BigInteger blindedMessage)
        {
            return blindedMessage.ModPow(this.GetDFactor(), this.GetNFactor());
        }

        public BigInteger UnblindMessage(BigInteger bs)
        {
            return this.randomBigInt.ModInverse(this.GetNFactor()).Multiply(bs).Mod(this.GetNFactor());
        }

        public BigInteger GetMsgFromSignedData(BigInteger signed)
        {
            return signed.ModPow(this.GetEFactor(), this.GetNFactor());
        }

        public bool VerifySignature(BigInteger unblinded)
        {
            //signature of m should = (m^d) mod n
            BigInteger sig_of_m = this.GetRawMessage().ModPow(this.GetDFactor(), this.GetNFactor());
            return unblinded.Equals(sig_of_m);
        }

        private AsymmetricCipherKeyPair GenerateKeyPair(int bitStrength)
        {
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), bitStrength);
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();

            keyGen.Init(keyGenerationParameters);
            return keyGen.GenerateKeyPair();
        }

        private BigInteger randomBigInt;

        private RsaKeyParameters PrivateKey
        {
            get;
        }

        private BigInteger GetDFactor()
        {
            return this.PrivateKey.Exponent;
        }

        private BigInteger GetNFactor()
        {
            return this.PublicKey.Modulus;
        }

        private BigInteger GetEFactor()
        {
            return this.PublicKey.Exponent;
        }


        private BigInteger GenerateRandomRelativelyPrimeBigInteger()
        {
            BigInteger tempRandomBigInt = new BigInteger("0");

            do
            {
                tempRandomBigInt = GenerateRandomBigInteger();
            }
            while (this.AreRelativelyPrime(tempRandomBigInt, this.GetNFactor()));

            return tempRandomBigInt;
        }

        private BigInteger GenerateRandomBigInteger()
        {
            byte[] randomBytes = new byte[20];
            SecureRandom random = new SecureRandom();

            random.NextBytes(randomBytes);
            return new BigInteger(1, randomBytes);
        }

        private bool AreRelativelyPrime(BigInteger first, BigInteger second)
        {
            BigInteger one = new BigInteger("1");
            BigInteger gcd = first.Gcd(second);
            return !gcd.Equals(one) || first.CompareTo(second) >= 0 || first.CompareTo(one) <= 0;
        }
    }
}
