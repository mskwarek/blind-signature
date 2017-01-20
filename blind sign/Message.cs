using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;

namespace BlindSign
{
    public class Message
    {
        public Message(string msg)
        {
            KeyGenerationParameters para = new KeyGenerationParameters(new SecureRandom(), 1024);
            //generate the RSA key pair
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            //initialise the KeyGenerator with a random number.
            keyGen.Init(para);
            AsymmetricCipherKeyPair keypair = keyGen.GenerateKeyPair();
            this.PrivateKey = (RsaKeyParameters)keypair.Private;
            this.PublicKey = (RsaKeyParameters)keypair.Public;

            this.message = msg;

            this.GenerateRandomBigInteger();
        }

        public String message
        {
            get;
        }

        private BigInteger r;

        public RsaKeyParameters PublicKey
        {
            get;
        }

        public RsaKeyParameters PrivateKey
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

        private BigInteger GetRawMessage()
        {
            byte[] raw = System.Text.Encoding.ASCII.GetBytes(message);
            return new BigInteger(raw);
        }

        public BigInteger getMessage()
        {

            
            return null;
        }

        public BigInteger BlindMessage()
        {
           //********************* BLIND ************************************

            return ((r.ModPow(this.GetEFactor(), this.GetNFactor())).Multiply(this.GetRawMessage())).Mod(this.GetNFactor());         
        }

        public BigInteger SignBlindedMessage(BigInteger blindedMessage)
        {

            //********************* SIGN *************************************
            return blindedMessage.ModPow(this.GetDFactor(), this.GetNFactor());
        }

        public BigInteger UnblindMessage(BigInteger bs)
        {
            //********************* UNBLIND **********************************       
            return ((r.ModInverse(this.GetNFactor())).Multiply(bs)).Mod(this.GetNFactor());
        }

        public BigInteger GetMsgFromSignedData(BigInteger signed)
        {
            //try to verify using the RSA formula
            return signed.ModPow(this.GetEFactor(), this.GetNFactor());
        }

        public bool VerifySignature(BigInteger unblinded)
        {
            //********************* VERIFY ***********************************
            
	        //signature of m should = (m^d) mod n
	        BigInteger sig_of_m = this.GetRawMessage().ModPow(this.GetDFactor(), this.GetNFactor());
	        Console.WriteLine("sig_of_m = " + sig_of_m);
	        
	        //check that s is equal to a signature of m:
	        return unblinded.Equals(sig_of_m);        
        }

        private void GenerateRandomBigInteger()
        {
            BigInteger n = this.PublicKey.Modulus;
            byte[] randomBytes = new byte[10];
            SecureRandom random = new SecureRandom();

            BigInteger gcd = null;
            BigInteger one = new BigInteger("1");

            //check that gcd(r,n) = 1 && r < n && r > 1
            do
            {
                random.NextBytes(randomBytes);
                r = new BigInteger(1, randomBytes);
                gcd = r.Gcd(n);
                Console.WriteLine("gcd: " + gcd);
            }
            while (!gcd.Equals(one) || r.CompareTo(n) >= 0 || r.CompareTo(one) <= 0);
        }
    }
}
