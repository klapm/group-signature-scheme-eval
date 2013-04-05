/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.common.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * (Big-) Integer-related utility functionality.
 * 
 * Contains the integer-to-bitstring and bitstring-to-integer conversion
 * as defined in Annex B of ISO 20008-2.2 as well as some additional integer
 * operations.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 *
 */
public class IntegerUtil
{
  /** '0' as a {@link BigInteger} */
  public static final BigInteger ZERO = BigInteger.ZERO;

  /** '1' as a {@link BigInteger} */
  public static final BigInteger ONE = BigInteger.ONE;

  /** '2' as a {@link BigInteger} */
  public static final BigInteger TWO = BigInteger.valueOf(2);

  /** '3' as a {@link BigInteger} */
  public static final BigInteger THREE = BigInteger.valueOf(3);

  /** '4' as a {@link BigInteger} */
  public static final BigInteger FOUR = BigInteger.valueOf(4);

  /** '5' as a {@link BigInteger} */
  public static final BigInteger FIVE = BigInteger.valueOf(5);

  /** '6' as a {@link BigInteger} */
  public static final BigInteger SIX  = BigInteger.valueOf(6);

  /** '7' as a {@link BigInteger} */
  public static final BigInteger SEVEN = BigInteger.valueOf(7);

  /** '8' as a {@link BigInteger} */
  public static final BigInteger EIGHT = BigInteger.valueOf(8);

  /** '9' as a {@link BigInteger} */
  public static final BigInteger NINE = BigInteger.valueOf(9);

  /** '10' as a {@link BigInteger} */
  public static final BigInteger TEN = BigInteger.TEN;

  /**
   * bit-string to integer conversion. Basically falls back to
   * the {@link BigInteger} byte[] constructor.
   * 
   * @param in the byte[] to convert
   * @return the resulting {@link BigInteger}
   */
  public static final BigInteger bs2ip(byte[] in)
  {
    return new BigInteger(1, in);
  }
  
  /**
   * integer to bit-string conversion, see 
   * {@link IntegerUtil#i2bsp(BigInteger, int)} for details.
   * 
   * @param in the long to convert
   * @return the resulting byte array
   */
  public static final byte[] i2bsp(long in)
  {
    return i2bsp(BigInteger.valueOf(in));
  }

  /**
   * integer to bit-string conversion, see 
   * {@link IntegerUtil#i2bsp(BigInteger, int)} for details.
   * 
   * @param in the long to convert
   * @param bit_len the target bit length
   * @return the resulting byte array
   */
  public static final byte[] i2bsp(long in, int bit_len)
  {
    return i2bsp(BigInteger.valueOf(in), bit_len);
  }
  
  /**
   * integer to bit-string conversion, see 
   * {@link IntegerUtil#i2bsp(BigInteger, int)} for details.
   * 
   * Uses {@link BigInteger#toByteArray()}. Note that leading zeroes prependend
   * by {@link BigInteger} are stripped off (hence that {@link #bs2ip(byte[])}
   * always assumes positive values). Otherwise, this causes probles
   * when concatenating big integers for subsequent hashing and on similar
   * operations.
   * 
   * @param in the {@link BigInteger} to convert
   * @return the resulting byte array
   */
  public static final byte[] i2bsp(BigInteger in)
  {
    byte[] ret = in.toByteArray();
    if(ret.length > 1 && ret[0] == 0)
      return Arrays.copyOfRange(ret, 1, ret.length);
    
    return ret;
  }

  /**
   * integer to bit-string conversion. Converts the given {@link BigInteger}
   * using {@link BigInteger#toByteArray()}, but enforces the array to be
   * of length {@code bit_len} by pre-pending zero-values.
   *  
   * @param in the {@link BigInteger} to convert
   * @param bit_len the target length of the bit-string in bits
   * @return the resulting byte array
   */
  public static final byte[] i2bsp(BigInteger in, int bit_len)
  {
    if(in.signum() < 0 || bit_len < 0)
      throw new IllegalArgumentException("Only positive inputs allowed");
        
    byte[] ba  = new byte[(int) Math.ceil((double) bit_len/8)];
    byte[] val = i2bsp(in);
    
    if(val.length > ba.length)
      throw new ArithmeticException("Bitlength too short"); 

    System.arraycopy(val, 0, ba, ba.length-val.length, val.length);
    return ba;      
  }
  
  /**
   * Tests whether a given {@link BigInteger} is odd. Convience-wrapper
   * for {@link BigInteger#testBit(int)}.
   * 
   * @param in The {@link BigInteger} to test
   * @return true if odd, false otherwise
   */
  public static final boolean isOdd(BigInteger in)
  {
    return in.testBit(0);
  }
  
  /**
   * computes (a|p) with p being a prime. Internally, the legendre symbol
   * is computed using it's generalization, the jacobi symbol.
   * See {{@link #jacobiSymbol(BigInteger, BigInteger)}.
   * 
   * @param a the number to test for quadratic reciprocity
   * @param p the prime modulus
   * @return  1 if a is a quadratic residue modulo p and a != 0 mod p,
   *         -1 if a is a quadratic non-residue modulo p,
   *          0 if a = 0 mod p
   */
  public static final int legendreSymbol(BigInteger a, BigInteger p)
  {
    return jacobiSymbol(a, p);
  }
  
  /**
   * Computes the jacobi symbol of a given number and modulus.
   * Code was taken from the jPBC (with minor adjustments, though).
   * 
   * @param a the number to test for quadratic reciprocity
   * @param p the prime modulus
   * @return  1 if a is a quadratic residue modulo p and a != 0 mod p,
   *         -1 if a is a quadratic non-residue modulo p,
   *          0 if a = 0 mod p
   */
  public static final int jacobiSymbol(BigInteger a, BigInteger p)
  {
    if(!p.testBit(0)) // even number.. wait what?
      throw new ArithmeticException("p needs to be a prime > 2");
    
    if(p.equals(TWO) || p.signum() < 1)
      return a.testBit(0) ? 1 : 0;
    
    if (ZERO.equals(a))
      return 0; // (0/n) = 0

    if (a.equals(ONE))
      return 1; // (1/n) = 1
    
    int j = 1;
    while(a.signum() != 0) {
      
      if (a.signum() < 0) {
        a = a.negate();    // (a/n) = (-a/n)*(-1/n)
        if(p.testBit(0) && p.testBit(1)) // p = 3 mod 4
          j = -j;
      }

      while(!a.testBit(0)) {
        a = a.shiftRight(1);
        
        // p = 3 mod 8 or p = 5 mod 8
        if (p.testBit(0) && (p.testBit(1) ^ (p.testBit(2))))
          j = -j;
      }

      // Property (iv)
      BigInteger temp = a;
      a    = p;
      p    = temp;

      // a = 3 mod 4 && p = 3 mod 4
      if (a.testBit(0) && a.testBit(1) && p.testBit(0) && p.testBit(1))
        j = -j;

      a = a.mod(p);
      if (a.compareTo(p.shiftRight(1)) > 0) 
        a = a.subtract(p);
    }

    if (p.equals(ONE))
      return j;
  
    return 0;
  }
  
  /**
   * Creates a {@link BigInteger} from a hexadecimal string. Spaces in the
   * String are removed.
   * 
   * @param str the hex-string
   * @return a {@link BigInteger} representing the string value
   */
  public static final BigInteger fromHexString(String str)
  {
    return new BigInteger(str.replace(" ", ""), 16);
  }
  
  /**
   * Chooses a random {@link BigInteger} from QR(n) by applying the tests
   * as defined in ISO20008-2.2, for example in step 3 of 6.2.2 "key generation
   * process". 
   * 
   * @param n the modulus
   * @param rnd a (secure) random object
   * @return a randomly chosen number between 0 and n.bitLength()
   */
  public static final BigInteger chooseRandomInQR(BigInteger n, Random rnd)
  {
    BigInteger gen = null;
    do {
      gen = new BigInteger(n.bitLength(), rnd).mod(n);
    } while (!n.gcd(gen.add(     IntegerUtil.ONE)).equals(IntegerUtil.ONE) || 
             !n.gcd(gen.subtract(IntegerUtil.ONE)).equals(IntegerUtil.ONE));
    
    return gen.modPow(IntegerUtil.TWO, n);
  }
  
  /**
   * Tests whether a given {@link BigInteger} is in the following range:
   * [-2^range, 2^(eps * range)-1] (inclusive).
   * 
   * @param in The {@link BigInteger} to test
   * @param range the bit-range specifier
   * @param eps an epsilon that's applied on the positive interval
   * @return true if it is in between the given range (inclusive),
   *         false otherwise
   */
  public static final boolean isInRange(BigInteger in, int range, double eps)
  {
    if(((in.signum() > 0) && (in.bitLength() > (int)(eps * range)) && 
        (in.compareTo(BigInteger.valueOf(1).shiftLeft(range)) > 0)) ||
       ((in.signum() < 0) && (in.bitLength() > range)              && 
        (in.compareTo(BigInteger.valueOf(-1).shiftLeft(range)) < 0)))
      return false;
    
    return true;
  }
  
  /**
   * This method basically covers step 23 of mechanism one in ISO20008-2.2.
   * See page 8 for reference. It generates a prime in the range of
   * [2^(lE) - 2^(le) + 1, 2^(lE) + 2^(le) - 1]
   * 
   * It generates a random between 0 and 2^le-1, sets the lE bit (lE > le)
   * and searches for a probable prime from there.
   * 
   * @param lE the upper bound
   * @param le the lower bound
   * @param rnd a (secure)random instance
   * @return a random prime in the specified range
   */
  public static final BigInteger 
  powerTwoDelimitedRandomPrime(int lE, int le, Random rnd)
  {
    BigInteger tmp = null;
    do { // just in case nextProbablePrime() leads to an 'overflow'
      tmp = new BigInteger(le, rnd).setBit(lE).nextProbablePrime();
    } while(tmp.testBit(le));
    
    return tmp;
  }
  
  /**
   * Returns a randomly chosen {@link BigInteger} of fixed bit length.
   * 
   * @param bitlen the target bit length
   * @param rnd a (secure)random instance
   * 
   * @return A random {@link BigInteger} of fixed bitlength
   */
  public static final BigInteger
  fixedWithRandomBigInteger(int bitlen, Random rnd)
  {
    byte[] random_bytes = new byte[(int) Math.ceil((double) bitlen/8)];
    rnd.nextBytes(random_bytes);
    // MSB is set to just to avoid a random zero there
    return new BigInteger(1, random_bytes).setBit(bitlen-1);
  }
  
  /**
   * Algorithm 3.35 for computing the Windowed non-adjacent form (wNAF) of a 
   * positive integer, as in 
   * Hankerson, Menezes, Vanstone "Guide to Elliptic Cryptography" 
   * 2nd ed., Springer, 2004
   * 
   * The wnaf is represented as byte array where each byte is a NAF-bit. Taken
   * from the jPBC source due to lazyness. So see BigIntegerUtils.naf() in
   * the jPBC source by Angelo De Caro at http://gas.dia.unisa.it/projects/jpbc/
   * 
   * @param n The {@link BigInteger} to compute the WNAF representation of
   * @param k The window size
   * 
   * @return The windowed non-adjacent form of n
   */
  public static final byte[] wnaf(BigInteger n, byte k)
  {    
    // wnaf representation is at most 1 bit longer
    byte[] wnaf = new byte[n.bitLength() + 1];
    
    BigInteger mod = ZERO.setBit(k).subtract(ONE);
    byte x = (byte) (1 << k);

    int lastnonzero = 0;
    for(int i = 0; n.signum() > 0; i++)
    {
      if(n.testBit(0))
      {
        wnaf[i] = n.and(mod).byteValue();
        if((wnaf[i] >> k - 1) > 0)
          wnaf[i] -= x;
        // wnaf[i] is now in [-2^(width-1), 2^(width-1)-1]
        
        n = n.subtract(BigInteger.valueOf(wnaf[i]));
        lastnonzero = i;
      }
      else
        wnaf[i] = 0;

      n = n.shiftRight(1);
    }

    // truncate it such that the first byte is non-zero
    return Arrays.copyOf(wnaf, ++lastnonzero);
  }
  
  /**
   * wNAF window size mapper. Maps from the given {@link BigInteger}s bit length
   * to a suitable window size. Taken from the jPBC as well. See 
   * BigIntegerUtils.naf() in the jPBC source by Angelo De Caro at 
   * http://gas.dia.unisa.it/projects/jpbc/
   * 
   * @param n The {@link BigInteger} to get a suitable window size of
   * 
   * @return A suitable window size
   */
  public static byte optimalPowWindowSize(BigInteger n) 
  {
    int expBits = n.bitLength();

    if (expBits > 9065)
      return 8;
    if (expBits > 3529)
      return 7;
    if (expBits > 1324)
      return 6;
    if (expBits > 474)
      return 5;
    if (expBits > 157)
      return 4;
    if (expBits > 47)
      return 3;
    return 2;
  }
  
  /**
   * Computes the EEA coefficients x, y of abs(a) and abs(b), such that
   * xa + yb = gcd(a,b).
   * 
   * @param a First {@link BigInteger}
   * @param b Second {@link BigInteger}
   * @return {x, y}
   */
  public static final BigInteger[] xgcd(BigInteger a, BigInteger b)
  {
    BigInteger x = ZERO, y = ONE, tmp;
    BigInteger[] out = { ONE, ZERO };
    a = a.abs(); b = b.abs();
    
    while(b.signum() > 0)
    {
      BigInteger[] qr = a.divideAndRemainder(b);
      tmp   = a;
      a     = b;
      b     = qr[1];
      
      tmp    = x;
      x      = out[0].subtract(qr[0].multiply(x));
      out[0] = tmp;
      
      tmp    = y;
      y      = out[1].subtract(qr[0].multiply(y));
      out[1] = tmp;
    }
    
    return out;
  }
  
  /**
   * Computes the square root of a {@link BigInteger}
   * 
   * @param n The {@link BigInteger} to compute the sqrt from
   * 
   * @return sqrt(n)
   */
  public static final BigInteger sqrt(BigInteger n)
  {    
    BigInteger a = BigInteger.ONE;
    BigInteger b = n.shiftRight(5).add(EIGHT);
    while(b.compareTo(a) >= 0)
    {
      BigInteger mid = a.add(b).shiftRight(1);
      if(mid.multiply(mid).compareTo(n) > 0)
        b = mid.subtract(BigInteger.ONE);
      else
        a = mid.add(BigInteger.ONE);
    }
    return a.subtract(BigInteger.ONE);
  }

}
