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
    
    class Program
    {
        public static void Main(string[] args)
        {
          try{

	        Message message = new Message();
	        
	        BigInteger e = message.PublicKey.Exponent;
	        BigInteger n = message.PublicKey.Modulus;
	        
	        //********************* VERIFY ***********************************
	        
	        BigInteger s = message.getMessage();
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
