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

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.AffinePoint;

/**
 * Useful utility functions for handling arrays and null-checking.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Util
{  
  /**
   * Takes a variable amount of {@link BigInteger}s as input, converts them to
   * a byte array and concatenates these arrays together in the order as given
   * in the parameter list.
   * 
   * @param bigints The {@link BigInteger}s to concatenate as byte arrays
   * @return The resulting merged byte array
   */
  public static final byte[] concatAsArrays(BigInteger... bigints)
  {
    byte[][] bytearrays = new byte[bigints.length][];
    for(int i = 0; i < bigints.length; i++)
      bytearrays[i] = IntegerUtil.i2bsp(bigints[i]);
    
    return concatArrays(bytearrays);
  }
    
  /**
   * Takes a variable amount of {@link BigInteger}s as input, converts them to
   * a byte array and concatenates these arrays together in the order as given
   * in the parameter list.
   * 
   * @param points The {@link AffinePoint}s to concatenate as byte arrays
   * @return The resulting merged byte array
   */
  public static final byte[] concatAsArrays(Point<?, ?>... points)
  {
    byte[][] bytearrays = new byte[points.length][];
    for(int i = 0; i < points.length; i++)
      bytearrays[i] = points[i].toByteArray();
    
    return concatArrays(bytearrays);
  }
  
  /**
   * Takes a variable amount of {@link BigInteger}s as input, converts them to
   * a byte array and concatenates these arrays together in the order as given
   * in the parameter list. Expands the resulting byte arrays so their byte-len
   * is Math.ceil(bit_len/8).
   * 
   * @param bit_len The length of each resulting array in bits
   * @param bigints The {@link BigInteger}s to concatenate as byte arrays
   * @return The resulting merged byte array
   */
  public static final byte[] concatAsExpandedArrays(int bit_len,
                                                    BigInteger... bigints)
  {
    byte[][] bytearrays = new byte[bigints.length][];
    for(int i = 0; i < bigints.length; i++)
      bytearrays[i] = IntegerUtil.i2bsp(bigints[i], bit_len);
    
    return concatArrays(bytearrays);
  }
  
  /**
   * Takes a variable amount of byte arrays as input and returns a merged
   * byte array by concatenating the input in the order of the parameterlist.
   * 
   * @param arrays the arrays to concatenate together
   * @return a merged byte array
   */
  public static final byte[] concatArrays(byte[]... arrays)
  {
    int length = 0;
    for(byte[] arr : arrays)
      length += arr.length;
    
    byte[] merged = new byte[length];
    int offset = 0;
    for(byte[] arr : arrays)
    {
      System.arraycopy(arr, 0, merged, offset, arr.length);
      offset += arr.length;
    }
    
    return merged;
  }
  
  /**
   * Takes a variable amount of {@link BigInteger} values to add to an existing
   * byte array and returns the merged one. New values are appended and order
   * as given.
   * 
   * @param array the arrays extend
   * @param values the values to add as {@link BigInteger}s
   * @return a merged byte array
   */
  public static final
  byte[] appendToArray(byte[] array, BigInteger... values)
  {
    return Util.concatArrays(array, Util.concatAsArrays(values));
  }
    
  /**
   * Takes a variable amount of {@link AffinePoint} values to add to an
   * existing byte array and returns the merged one. New values are appended
   * and order as given.
   * 
   * @param array the arrays extend
   * @param values the values to add as {@link AffinePoint}s
   * @return a merged byte array
   */
  public static final
  byte[] appendToArray(byte[] array, Point<?, ?>... values)
  {
    return Util.concatArrays(array, Util.concatAsArrays(values));
  }
    
  /**
   * Extracts a range of bytes from an existing byte array, starting at a given
   * position.
   * 
   * @param in the byte array to extract a subset from
   * @param offset the starting index
   * @param len the amount of bytes to extract
   * @return the extracted array
   */
  public static final byte[] extractBytes(byte[] in, int offset, int len)
  {
    byte[] dest = new byte[len];
    System.arraycopy(in, offset, dest, 0, len);
    return dest;
  }
    
  /**
   * Checks whether any of the given arguments is *not* null.
   * 
   * @param arguments a list of arguments to check
   * @return true if a null-value occurs, false otherwise
   */
  public static final boolean isAnyNotNull(Object... arguments)
  {
    for(Object arg: arguments)
      if(arg != null)
        return true;
    
    return false;
  }

  /**
   * Checks whether any of the given arguments is null.
   * 
   * @param arguments a list of arguments to check
   * @return false if no null-value occurs, true otherwise
   */
  public static final boolean isAnyNull(Object... arguments)
  {
    for(Object arg: arguments)
      if(arg == null)
        return true;
    
    return false;
  }
  
  /**
   * Returns whether 'ref' equals any of the objects in 'to_test'. Relies
   * on a working {@link #equals(Object)} implementation.
   * 
   * @param ref The reference object
   * @param to_test The objects to compare to
   * @return true if any object in to_test equals ref
   */
  public static final boolean equalsAnyOf(Object ref, Object... to_test)
  {
    for(Object t : to_test)
      if(ref.equals(t))
        return true;
    
    return false;
  }
}
