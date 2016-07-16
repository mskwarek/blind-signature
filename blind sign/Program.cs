using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
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
    class Message{
        public String message = "0101010101010101";
        
        public BigInteger m;

        public BigInteger getMessage(RsaKeyParameters pubKey, RsaKeyParameters privKey)
        {
            byte[] raw = System.Text.Encoding.ASCII.GetBytes(message);
            m = new BigInteger(raw);
            //RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            //generator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            
	    BigInteger s = null;
            try {
	            
	        
            	Console.WriteLine("\nm = " + m);
            	BigInteger e = pubKey.Exponent;
            	BigInteger d = privKey.Exponent;
	       
		SecureRandom random = new SecureRandom();
	        byte [] randomBytes = new byte[10];
	        BigInteger r = null;
	        BigInteger n = pubKey.Modulus;
	        BigInteger gcd = null;
	        BigInteger one = new BigInteger("1");


	        //check that gcd(r,n) = 1 && r < n && r > 1
	        do {
	            random.NextBytes(randomBytes);
	            r = new BigInteger(1, randomBytes);
	            gcd = r.Gcd(n);
	            Console.WriteLine("gcd: " + gcd);
	        }
	        while(!gcd.Equals(one) || r.CompareTo(n)>=0 || r.CompareTo(one)<=0);
	
	       //********************* BLIND ************************************
	        
	        BigInteger b = ((r.ModPow(e,n)).Multiply(m)).Mod(n);
	        Console.WriteLine("\nb = " + b);
	       
	        //********************* SIGN *************************************
	        
	        BigInteger bs = b.ModPow(d,n);
           	Console.WriteLine("bs = " + bs);
	        

	        //********************* UNBLIND **********************************       
	        s = ((r.ModInverse(n)).Multiply(bs)).Mod(n);
            	Console.WriteLine("s = " + s);

            	return s; 
	    }
	    catch(Exception ex) {
	        //System.out.println("ERROR Message: ");
            
	    }
           return null;
	}}
    class Program
    {
        

        public static void Main(string[] args)
        {
          try{
	        RsaKeyParameters pubKey;
	        RsaKeyParameters privKey;
	        KeyGenerationParameters para = new KeyGenerationParameters(new SecureRandom(), 1024);
	        //generate the RSA key pair
	        RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator(); 
	        //initialise the KeyGenerator with a random number.
	        keyGen.Init(para);
	        AsymmetricCipherKeyPair keypair = keyGen.GenerateKeyPair();
	        privKey = (RsaKeyParameters)keypair.Private;
	        pubKey = (RsaKeyParameters)keypair.Public;
	        Message message = new Message();
	        
	        BigInteger e = pubKey.Exponent;
	        BigInteger n = pubKey.Modulus;
	        
	        //********************* VERIFY ***********************************
	        
	        BigInteger s = message.getMessage(pubKey, privKey);
	        /*
	        //signature of m should = (m^d) mod n
	        BigInteger sig_of_m = m.modPow(d,n);
	        System.out.println("sig_of_m = " + sig_of_m);
	        
	        //check that s is equal to a signature of m:
	        System.out.println(s.equals(sig_of_m));
	        */
	        //try to verify using the RSA formula
	        BigInteger check = s.ModPow(e,n);
	        Console.WriteLine(message.m.Equals(check));
			
	        //BOTH TESTS RETURN FALSE - s must not be a valid signature of m 
	        
	        //byte[] array =	check.ToByteArray();
		//String str = System.Text.Encoding.ASCII.GetString(check.ToByteArray());
            	Console.WriteLine(System.Text.Encoding.ASCII.GetString(check.ToByteArray()));
	        Console.WriteLine("check = " +check);
            	Console.WriteLine("m = " + message.m);
            	string a = "";
            	Console.WriteLine(a);
            	Console.ReadLine();
	    }
	    catch(Exception ex) {
	        //System.out.println("ERROR: ");
	        //ex.printStackTrace();
            	Console.WriteLine("ERROR" + ex.StackTrace);
            	Console.ReadLine();
	    }
        }
    }
}
