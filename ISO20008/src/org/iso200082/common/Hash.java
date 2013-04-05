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

package org.iso200082.common;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;


/**
 * Hashing-related utility class that implements the hash functions as
 * specified in Annex B of the ISO20008-2.2 standard.
 * 
 * Note that this implementation does not perform any encoding to ensure unique
 * interpretability of the hashed values as recommended in section 4 ("Symbols")
 * of the ISO20008-2.2 draft. Otherwise it wouldn't meet the test data to be
 * found in Annex E.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Hash
{
  /**
   * Hash function wrapper returning a {@link BigInteger}.
   * See {@link #H(String, byte[], int)} for more info.
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   * @param raw_data The data to hash
   * @param k The target bit length
   * 
   * @return A {@link BigInteger} representing the digest
   */
  public static final BigInteger H(String hash_algorithm,
                                   byte[] raw_data, int k)
  {
    return IntegerUtil.bs2ip(HBytes(hash_algorithm, raw_data, k));
  }
  
  /**
   * Represents the actual hash function H (not described in Annex B, but
   * referred to various times in the mechanisms). It creates a digest
   * using the given hash algorithm and data and returns the k least relevant
   * bits of it.
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   * @param raw_data The data to hash
   * @param k The target bit length
   * 
   * @return A byte[] representing the digest
   */
  public static final byte[] HBytes(String hash_algorithm,
                                    byte[] raw_data, int k)
  {
    if(Util.isAnyNull(hash_algorithm, raw_data) || k < 0)
      throw new IllegalArgumentException("illegal arguments given");
    
    if(k % 8 != 0)
      throw new
      IllegalArgumentException("Bit length needs to be a multiple of 8");
    
    MessageDigest md = null;
    try
    {
      md = MessageDigest.getInstance(hash_algorithm);
    }
    catch(NoSuchAlgorithmException ex)
    {
      throw new IllegalArgumentException(ex);
    }
    
    int target_bytes = k/8;
    
    byte[] digest = md.digest(raw_data);
    
    // according to E.1 the least significant bits are relevant
    if(digest.length > target_bytes) 
      return Arrays.copyOfRange(digest, digest.length-target_bytes,
                                        digest.length);
    
    return digest;
  }
  
  /**
   * HL as defined in B.2. See {@link #HL(String, byte[], int)} for more info.
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   * @param raw_data The data to hash
   * @param k The target bit length
   * 
   * @return A BigInteger representing the digest
   */
  public static final BigInteger HL(String hash_algorithm,
                                    byte[] raw_data, int k)
  {
    return IntegerUtil.bs2ip(HLBytes(hash_algorithm, raw_data, k));
  }
    
  /**
   * HL as defined in B.2. Hashes any input of arbitrary length into a digest
   * of length {@code k}. If the chosen hashing algorithm does not
   * result in {@code k} output bits, MGF1 as defined in PKCS#1
   * is applied.
   * 
   * NOTE: Contrary to the standard definition, this imlementation returns
   *       not the *leading* but the *least significant* bits. Otherwise it
   *       would not match the accompanied test data from Annex E.
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   * @param raw_data The data to hash
   * @param k The target bit length
   * 
   * @return A byte[] representing the digest
   */
  public static final byte[] HLBytes(String hash_algorithm,
                                     byte[] raw_data, int k)
  {
    if(Util.isAnyNull(hash_algorithm, raw_data) || k < 0)
      throw new IllegalArgumentException("illegal arguments given");
    
    MessageDigest md = null;
    try
    {
      md = MessageDigest.getInstance(hash_algorithm);
    }
    catch(NoSuchAlgorithmException ex)
    {
      throw new IllegalArgumentException(ex);
    }
    
    int i = 0;
    md.update(raw_data);
    md.update(IntegerUtil.i2bsp(i, 32));
    byte[] T = md.digest();
    int    h = T.length;
    
    /*
     * Warning:
     * There is a off-by-one bug when compared to the correct MGF1 output,
     * see TestBugs.java in the unit-test project.
     * 
     * The following while-head should use '<' as comparison operator
     */
    while(++i <= Math.ceil((double) (k / 8) / h)) 
    {
      md.update(raw_data);
      md.update(IntegerUtil.i2bsp(i, 32));
      T = Util.concatArrays(T, md.digest());
    }
    
    /* 
     * Warning:
     * yet another bug, see TestBugs.java. Here, the reference implementation
     * seems to use the *trailing* k bits instead of the mentioned *leading* k
     * bits.
     */
    // should be: Arrays.copyOf(T, (int) Math.ceil((double) (k / 8)));
    return Arrays.copyOfRange(T, (int) (T.length-Math.ceil((double) (k / 8))),
                              T.length);
  }
  
  /**
   * HBS2PF2 as defined in B.2.
   * Hashes any input of arbitrary length into a digest within the given
   * field's boundaries. Non-jPBC version
   * 
   * Note that only HBS2PF2 is implemented as it is seemingly the only one
   * that has been used during the standard implementation (luckily, as I
   * did not have access to ISO/IEC 29150).
   * 
   * @param hash_algorithm The has algorithm
   * @param input The message/input to hash
   * @param field The target field
   * 
   * @return The hash, represented as a {@link BigInteger}
   */
  public static final <P> FqElement<P> 
  HBS2PF2(String hash_algorithm, byte[] input, Field<FqElement<P>, Fq<P>> field)
  {
    MessageDigest md = null;
    try
    {
      md = MessageDigest.getInstance(hash_algorithm);
    }
    catch(NoSuchAlgorithmException ex)
    {
      throw new IllegalArgumentException(ex);
    }
    
    byte[] digest = md.digest(input);
    if(digest.length*8 < field.getOrder().bitLength())
      throw new IllegalArgumentException("Digest needs to be at least as " +
                                         "long as p, choose another hash " +
                                         "algorithm");
    
    return field.getElementFromComponents(IntegerUtil.bs2ip(digest));
  }
  
  /**
   * Tries to hash some input to an elliptic curve point, as defined in
   * Annex B.4 of ISO20008-2.2. Non-jPBC version
   * 
   * @param hash_algorithm The hash algorithm to use (note that it has to
   *                       output at least the same amount of bits as the
   *                       target field's order)
   * @param input The message to hash
   * @param field The point's curve field
   * 
   * @return A point on the curve or null if it failed
   */
  public static final <P> Point<FqElement<P>, Fq<P>>
  HBS2ECP(String hash_algorithm, byte[] input, CurveField<FqElement<P>, Fq<P>> field)
  {
    FqElement<P> x;
    Point<FqElement<P>, Fq<P>> P;
    int i = 0;
    do {
      x = HBS2PF2(hash_algorithm,
                  Util.concatArrays(IntegerUtil.i2bsp(i++, 32), input),
                                    field.getField());
      P = field.getElementFromX(x);
      
      if(i == 0) // overflow
        return null; // could not hash to point
      
    } while(P.isInfinite());
    
    return P;    
  }
}
