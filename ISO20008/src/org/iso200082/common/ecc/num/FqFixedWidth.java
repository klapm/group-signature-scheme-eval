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

package org.iso200082.common.ecc.num;

import java.math.BigInteger;
import java.util.Random;

import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.elements.doubleprecision.FqDoubleElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.util.Creator;
import org.iso200082.common.util.RecycleBin;


/**
 * Primitive implementation working directly on fixed-width integer arrays.
 * 
 * Incorporates both single- and double precision elements. Does element
 * recycling, both the element instances as well as the fixed-width int[]s.
 * 
 * The main benefit results from the equal-sized int[]s, which are very 
 * convenient to recycle and thus avoids a lot of instantiations.
 * 
 * Unfortunately, parts of this implementation were inspired by the commercial
 * ECCelerate library of the IAIK and Stiftung Secure Information and
 * Communication Technologies (SIC), see 
 * https://jce.iaik.tugraz.at/sic/Products/Core-Crypto-Toolkits/ECCelerate.
 * 
 * Therefore, parts are omitted. Hence, this implementation is not going to
 * work as-is. The remainder is left here, however, to keep the recycling
 * optimizations and other surroundings in place.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class FqFixedWidth extends Fq<int[]>
{  
  /** modulus */
  protected int[]      q;
  
  /** q+1 >> 1 */
  protected int[]  divTwo;
  
  /** q+1 >> 2 */
  protected int[]  divFour;
  
  private int VALUE_LENGTH;
  
  /* recyclers for both the single- and double-precision elements as well as 
   * the internally used int[]s as well */
  private RecycleBin<int[], int[]> single_array_recycler;
  private RecycleBin<int[], int[]> double_array_recycler;
  private RecycleBin<SingleFixedWidthElement, int[]> single_recycler;
  private RecycleBin<DoubleFixedWidthElement, int[]> double_recycler;
  
  /** nullified single-precision array */
  public static int[] nullarray;
  
  /** nullified double-precision array */
  public static int[] dblnullarray;
  
  /**
   * Ctor, initialized with a rng and the order to use
   * 
   * @param random The rng
   * @param order  The modulus
   */
  public FqFixedWidth(Random random, BigInteger order)
  {
    super(random, order);
    
    VALUE_LENGTH = (order.bitLength() >>> 5) + 2;
    
    nullarray    = new int[VALUE_LENGTH];
    dblnullarray = new int[2*VALUE_LENGTH];
    
    // recycling stuff (looks like overhead, but boooooosts :-))
    single_recycler = new RecycleBin<SingleFixedWidthElement, int[]>(
                      new SingleFixedWidthElement[50], new SingleCreator());
    double_recycler = new RecycleBin<DoubleFixedWidthElement, int[]>(
                      new DoubleFixedWidthElement[20], new DoubleCreator());
    Creator<int[], int[]> array_creator = new IntArrayCreator();
    single_array_recycler = new RecycleBin<int[], int[]>(
                            new int[50][VALUE_LENGTH], array_creator);
    double_array_recycler = new RecycleBin<int[], int[]>(
                            new int[20][VALUE_LENGTH], array_creator);
    
    // remainder omitted. not all values are initialized!
  }
  
  @Override
  public FqElement<int[]> getElementFromByteArray(byte[] data)
  {
    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> getElementFromComponents(
      BigInteger... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");
    
    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> getElementFromComponents(long... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");

    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  public FqElement<int[]> getElementFromComponents(int radix,
      String... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");

    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public boolean isMontgomery()
  {
    return false;
  }

  @Override
  public Fq<int[]> getNonMontgomery()
  {
    return this;
  }

  @Override
  @SuppressWarnings("unchecked")
  public FqElement<int[]> getElementFromComponents(FqElement<int[]>... elements)
  {
    if(elements.length != getNumberOfCoefficients())
      throw new IllegalArgumentException("There is only one component in Fq");

    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> fromDouble(FqDoubleElement<int[]> dbl)
  {
    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> getRandomElement()
  {
    return single_recycler.get(single_array_recycler.get(nullarray));
  }

  @Override
  public FqElement<int[]> getOneElement()
  {
    int[] one = single_array_recycler.get(nullarray);
    one[0] = 1;
    return single_recycler.get(one);
  }

  @Override
  public FqElement<int[]> getZeroElement()
  {
    // dummy.
    return single_recycler.get(single_array_recycler.get(nullarray));
  }
  
  @Override
  public FqElement<int[]> getTwoElement()
  {
    int[] two = single_array_recycler.get(nullarray);
    two[0] = 2;
    return single_recycler.get(two);
  }

  @Override
  public Fq<int[]> getNew(BigInteger modulus)
  {
    return new FqFixedWidth(rnd, modulus);
  }
  
  @Override
  public Fq<int[]> getNonMontgomery(BigInteger modulus)
  {
    return getNew(modulus);
  }
  
  private class SingleFixedWidthElement extends FqElement<int[]>
  {
    
    public SingleFixedWidthElement(Fq<int[]> target_field, int[] value)
    {
      super(target_field, value);
    }
    
    public SingleFixedWidthElement(Fq<int[]> target_field, BigInteger bi)
    {
      // dummy.
      super(target_field, single_array_recycler.get(nullarray));
    }
    
    public SingleFixedWidthElement(Fq<int[]> target_field, byte[] ba)
    {
      // dummy.
      super(target_field, (int[]) null);
    }    
    
    @Override
    public boolean equals(Object obj)
    {
      if(obj == this)
        return true;
      
      if((obj == null) || !(obj instanceof SingleFixedWidthElement))
        return false;
      
      // dummy.
      return true;
    }

    @Override
    public FqElement<int[]> add(FqElement<int[]> element)
    {
      return clone().addMutable(element);
    }

    @Override
    public FqElement<int[]> addMutable(FqElement<int[]> element)
    {
      // dummy.
      return this;
    }
    
    @Override
    public FqElement<int[]> sub(FqElement<int[]> element)
    {
      return clone().subMutable(element);
    }

    @Override
    public FqElement<int[]> subMutable(FqElement<int[]> element)
    {

      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> mul(FqElement<int[]> element)
    {
      return clone().mulMutable(element);
    }

    @Override
    public FqElement<int[]> mulMutable(FqElement<int[]> element)
    {     
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> mul(BigInteger bi)
    {
      return clone().mulMutable(bi);
    }

    @Override
    public FqElement<int[]> mulMutable(BigInteger bi)
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> negate()
    {
      return clone().negateMutable();
    }

    @Override
    public FqElement<int[]> negateMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> invert()
    {
      return clone().invertMutable();
    }

    @Override
    public FqElement<int[]> invertMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> square()
    {
      return clone().squareMutable();
    }

    @Override
    public FqElement<int[]> squareMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> twice()
    {
      return add(this);
    }

    @Override
    public FqElement<int[]> twiceMutable()
    {
      return addMutable(this);
    }

    @Override
    public FqElement<int[]> sqrt()
    {
      return clone().sqrtMutable();
    }

    @Override
    public FqElement<int[]> sqrtMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public byte[] toByteArray()
    {
      return toBigInteger().toByteArray();
    }

    @Override
    public boolean isZero()
    {
      // dummy.
      return true;
    }

    @Override
    public boolean isOne()
    {
      // dummy.
      return true;
    }

    @Override
    public FqElement<int[]> clone()
    {
      // this is somewhat important.
      return single_recycler.get(single_array_recycler.get(value));
    }

    @Override
    public BigInteger toBigInteger()
    {
      // dummy.
      return BigInteger.valueOf(42);
    }

    @Override
    public FqElement<int[]> addNoReduction(FqElement<int[]> element)
    {
      return clone().addNoReductionMutable(element);
    }
    
    public FqElement<int[]> addNoReductionMutable(FqElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> subNoReduction(FqElement<int[]> element)
    {
      return clone().subNoReductionMutable(element);
    }
    
    @Override
    public FqElement<int[]> subNoReductionMutable(FqElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> twiceNoReduction()
    {
      return addNoReduction(this);
    }

    @Override
    public FqDoubleElement<int[]> mulDouble(FqElement<int[]> element)
    {
      // dummy.
      return double_recycler.get(double_array_recycler.get(dblnullarray));
    }

    @Override
    public FqDoubleElement<int[]> squareDouble()
    {
      // dummy.
      return double_recycler.get(double_array_recycler.get(dblnullarray));
    }

    @Override
    public FqElement<int[]> divByTwo()
    {
      return clone().divByTwoMutable();
    }

    @Override
    public FqElement<int[]> divByTwoMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public FqElement<int[]> divByFour()
    {
      return clone().divByFourMutable();
    }

    @Override
    public FqElement<int[]> divByFourMutable()
    {
      // dummy.
      return this;
    }

    @Override
    public void recycle()
    {
      single_array_recycler.put(value);
      single_recycler.put(this);
    }
  }
  
  private class DoubleFixedWidthElement extends FqDoubleElement<int[]>
  {

    public DoubleFixedWidthElement(int[] value)
    {
      super(value);
    }
    
    @Override
    public boolean equals(Object obj)
    {
      if(obj == this)
        return true;
      
      if((obj == null) || !(obj instanceof DoubleFixedWidthElement))
        return false;

      // dummy.
      return true;
    }

    @Override
    public FqDoubleElement<int[]> add(FqDoubleElement<int[]> element)
    {
      return clone().addMutable(element);
    }

    @Override
    public FqDoubleElement<int[]> addMutable(FqDoubleElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqDoubleElement<int[]> sub(FqDoubleElement<int[]> element)
    {
      return clone().subMutable(element);
    }

    @Override
    public FqDoubleElement<int[]> subMutable(FqDoubleElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqDoubleElement<int[]> twice()
    {
      return clone().addMutable(this);
    }

    @Override
    public FqDoubleElement<int[]> twiceMutable()
    {
      return addMutable(this);
    }

    @Override
    public FqElement<int[]> mod()
    {
      return fromDouble(this);
    }

    @Override
    public Fq<int[]> getField()
    {
      return FqFixedWidth.this;
    }

    @Override
    public byte[] toByteArray()
    {
      // dummy.
      return new byte[] { 0x42 };
    }

    @Override
    public boolean isZero()
    {
      // dummy.
      return true;
    }

    @Override
    public boolean isOne()
    {
      // dummy.
      return true;
    }

    @Override
    public FqDoubleElement<int[]> subOpt1(FqDoubleElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqDoubleElement<int[]> subNoReductionMutable(FqDoubleElement<int[]> element)
    {
      // dummy.
      return this;
    }

    @Override
    public FqDoubleElement<int[]> addMutable(int[] bi)
    {
      // dummy.
      return this;
    }

    @Override
    public BigInteger toBigInteger()
    {
      // dummy.
      return BigInteger.valueOf(42);
    }

    @Override
    public FqDoubleElement<int[]> clone()
    {
      // this is somewhat important.
      return double_recycler.get(double_array_recycler.get(value));
    }

    @Override
    public void recycle()
    {
      double_array_recycler.put(value);
      double_recycler.put(this);
    }    
  }

  @Override
  public void recycle(FqElement<int[]> element)
  {
    single_array_recycler.put(element.value);
    single_recycler.put((SingleFixedWidthElement) element);
  }

  /*
   * single-precision creator
   */
  private class SingleCreator implements Creator<SingleFixedWidthElement, int[]>
  {

    @Override
    public SingleFixedWidthElement create(int[]... values)
    {
      return new SingleFixedWidthElement(FqFixedWidth.this, values[0]);
    }

    @Override
    public SingleFixedWidthElement fromObject(SingleFixedWidthElement obj, int[]... values)
    {
      obj.value = values[0];
      return obj;
    }
    
  }
  
  /*
   * double-precision creator
   */
  private class DoubleCreator implements Creator<DoubleFixedWidthElement, int[]>
  {

    @Override
    public DoubleFixedWidthElement create(int[]... values)
    {
      return new DoubleFixedWidthElement(values[0]);
    }

    @Override
    public DoubleFixedWidthElement fromObject(DoubleFixedWidthElement obj,
        int[]... values)
    {
      obj.value = values[0];
      return obj;
    }
    
  }

  /*
   * integer array creator
   */
  private class IntArrayCreator implements Creator<int[], int[]>
  {

    @Override
    public int[] create(int[]... values)
    {
      int[] tmp = new int[values[0].length];
      System.arraycopy(values[0], 0, tmp, 0, tmp.length);
      return tmp;
    }

    @Override
    public int[] fromObject(int[] obj, int[]... values)
    {
      System.arraycopy(values[0], 0, obj, 0, obj.length);
      return obj;
    }
    
  }
}
