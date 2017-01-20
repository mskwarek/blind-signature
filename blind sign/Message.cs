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

namespace blind_sign
{
    class Message
    {
        public Message()
        {
            KeyGenerationParameters para = new KeyGenerationParameters(new SecureRandom(), 1024);
            //generate the RSA key pair
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            //initialise the KeyGenerator with a random number.
            keyGen.Init(para);
            AsymmetricCipherKeyPair keypair = keyGen.GenerateKeyPair();
            this.PrivateKey = (RsaKeyParameters)keypair.Private;
            this.PublicKey = (RsaKeyParameters)keypair.Public;
   
        }
        public String message = "0101010101010101";

        public BigInteger m;

        public RsaKeyParameters PublicKey
        {
            get;
        }

        public RsaKeyParameters PrivateKey
        {
            get;
        }

        public BigInteger getMessage()
        {
            byte[] raw = System.Text.Encoding.ASCII.GetBytes(message);
            m = new BigInteger(raw);

            BigInteger s = null;
            try
            {


                Console.WriteLine("\nm = " + m);
                BigInteger e = this.PublicKey.Exponent;
                BigInteger d = this.PrivateKey.Exponent;

                SecureRandom random = new SecureRandom();
                byte[] randomBytes = new byte[10];
                BigInteger r = null;
                BigInteger n = this.PublicKey.Modulus;
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

                //********************* BLIND ************************************

                BigInteger b = ((r.ModPow(e, n)).Multiply(m)).Mod(n);
                Console.WriteLine("\nb = " + b);

                //********************* SIGN *************************************

                BigInteger bs = b.ModPow(d, n);
                Console.WriteLine("bs = " + bs);


                //********************* UNBLIND **********************************       
                s = ((r.ModInverse(n)).Multiply(bs)).Mod(n);
                Console.WriteLine("s = " + s);

                return s;
            }
            catch (Exception ex)
            {
                //System.out.println("ERROR Message: ");

            }
            return null;
        }
    }
}
