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
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.RecycleBin;

/**
 * Primitive implementation using {@link BigInteger}.
 * 
 * Incorporates both single- and double precision elements. Does element
 * recycling (fields only, though, as {@link BigInteger}s are mutable).
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class FqBigInteger extends Fq<BigInteger>
{
  /** q+1 >> 1 */
  private BigInteger divTwo;
  
  /** q+1 >> 2 */
  private BigInteger divFour;
  
  /** some non-quadratic residue for sqrt */
  private BigInteger nqr;
  
  /** single precision element recycler */
  private RecycleBin<FqBigIntegerElement, BigInteger> single_recycler;
  
  /** double precision element recycler */
  private RecycleBin<FqDoubleBigIntegerElement, BigInteger> double_recycler;
  
  /**
   * Ctor, initialized with a rng and the order to use
   * 
   * @param random The rng
   * @param order  The modulus
   */
  public FqBigInteger(Random random, BigInteger order)
  {
    super(random, order);
    
    divTwo  = order.add(BigInteger.ONE).shiftRight(1);
    divFour = divTwo.shiftRight(1);

    qn = order.shiftLeft(order.bitLength());
    
    single_recycler = new RecycleBin<FqBigIntegerElement, BigInteger>(
                      new FqBigIntegerElement[50], new SingleCreator());
    double_recycler = new RecycleBin<FqDoubleBigIntegerElement, BigInteger>(
                      new FqDoubleBigIntegerElement[20], new DoubleCreator());
  }
  
  /* NQR getter */
  private BigInteger getNqr()
  {
    if(nqr == null)
      do
      {
        nqr = new BigInteger(order.bitLength()-1, rnd);
      } while(IntegerUtil.legendreSymbol(nqr, order) == 1 || nqr.signum() == 0);
    return nqr;
  }

  @Override
  public FqElement<BigInteger> getRandomElement()
  {
    return single_recycler.get(new BigInteger(order.bitLength(), rnd)
                          .mod(order));
  }

  @Override
  public FqElement<BigInteger> getOneElement()
  {
    return single_recycler.get(BigInteger.ONE);
  }

  @Override
  public FqElement<BigInteger> getZeroElement()
  {
    return single_recycler.get(BigInteger.ZERO);
  }

  @Override
  public FqElement<BigInteger> getTwoElement()
  {
    return single_recycler.get(BigInteger.valueOf(2));
  }

  @Override
  public FqElement<BigInteger> getElementFromByteArray(byte[] data)
  {
    return single_recycler.get(new BigInteger(1, data).mod(order));
  }

  @Override
  public FqElement<BigInteger> getElementFromComponents(
      BigInteger... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");
    
    return single_recycler.get(components[0].mod(order));
  }

  @Override
  public FqElement<BigInteger> getElementFromComponents(long... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");
    
    return single_recycler.get(BigInteger.valueOf(components[0]).mod(order));
  }

  @Override
  public FqElement<BigInteger> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  @SuppressWarnings("unchecked")
  public FqElement<BigInteger> getElementFromComponents(
      FqElement<BigInteger>... elements)
  {
    if(elements.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");
    
    return getElementFromComponents(elements[0].value);
  }

  @Override
  public FqElement<BigInteger> getElementFromComponents(int radix,
      String... components)
  {
    if(components.length != 1)
      throw new IllegalArgumentException("There is only one component in Fq");
    
    return single_recycler.get(new BigInteger(components[0], radix).mod(order));
  }

  @Override
  public boolean isMontgomery()
  {
    return false;
  }

  @Override
  public Fq<BigInteger> getNonMontgomery()
  {
    return this;
  }

  @Override
  public FqElement<BigInteger> fromDouble(FqDoubleElement<BigInteger> dbl)
  {
    return single_recycler.get(dbl.value.mod(order));
  }

  @Override
  public Fq<BigInteger> getNew(BigInteger modulus)
  {
    return new FqBigInteger(rnd, modulus);
  }

  @Override
  public Fq<BigInteger> getNonMontgomery(BigInteger modulus)
  {
    return getNew(modulus);
  }

  @Override
  public void recycle(FqElement<BigInteger> element)
  {
    single_recycler.put((FqBigIntegerElement) element);
  }
  
  /**
   * Single precision element implementation
   */
  private class FqBigIntegerElement extends FqElement<BigInteger>
  {

    public FqBigIntegerElement(Fq<BigInteger> target_field, BigInteger value)
    {
      super(target_field, value);
    }

    @Override
    public FqElement<BigInteger> add(FqElement<BigInteger> element)
    {
      return clone().addMutable(element);
    }

    @Override
    public FqElement<BigInteger> addMutable(FqElement<BigInteger> element)
    {
      value = value.add(element.value);
      if(value.compareTo(order) >= 0)
        value = value.subtract(order);
      
      return this;
    }

    @Override
    public FqElement<BigInteger> sub(FqElement<BigInteger> element)
    {
      return clone().subMutable(element);
    }

    @Override
    public FqElement<BigInteger> subMutable(FqElement<BigInteger> element)
    {
      if(value.compareTo(element.value) < 0)
        value = value.add(order);
      
      value = value.subtract(element.value);
      return this;
    }

    @Override
    public FqElement<BigInteger> mul(FqElement<BigInteger> element)
    {
      return clone().mulMutable(element);
    }

    @Override
    public FqElement<BigInteger> mulMutable(FqElement<BigInteger> element)
    {
      value = value.multiply(element.value).mod(order);
      return this;
    }

    @Override
    public FqElement<BigInteger> mul(BigInteger bi)
    {
      return clone().mulMutable(bi);
    }

    @Override
    public FqElement<BigInteger> mulMutable(BigInteger bi)
    {
      value = value.multiply(bi).mod(order);
      return this;
    }

    @Override
    public FqElement<BigInteger> negate()
    {
      return clone().negateMutable();
    }

    @Override
    public FqElement<BigInteger> negateMutable()
    {
      value = order.subtract(value);
      return this;
    }

    @Override
    public FqElement<BigInteger> invert()
    {
      return clone().invertMutable();
    }

    @Override
    public FqElement<BigInteger> invertMutable()
    {
      value = value.modInverse(order);
      return this;
    }

    @Override
    public FqElement<BigInteger> square()
    {
      return mul(this);
    }

    @Override
    public FqElement<BigInteger> squareMutable()
    {
      return mulMutable(this);
    }

    @Override
    public FqElement<BigInteger> twice()
    {
      return add(this);
    }

    @Override
    public FqElement<BigInteger> twiceMutable()
    {
      return addMutable(this);
    }

    @Override
    public FqElement<BigInteger> sqrt()
    {
      return clone().sqrtMutable();
    }

    @Override
    public FqElement<BigInteger> sqrtMutable()
    {
      if(IntegerUtil.legendreSymbol(value, order) != 1)
        return null;

      BigInteger e1    = order.subtract(BigInteger.ONE).shiftRight(1); 
      BigInteger e1tmp = e1;
      BigInteger e2    = order.subtract(BigInteger.ONE);               
      
      int s;
      for(s = 0; !e1.testBit(s); s++);
      
      BigInteger k = e1.shiftRight(s);
      BigInteger tmp;
      for(int i = 1; i <= s; i++)
      {
        e1  = e1.shiftRight(1);
        e2  = e2.shiftRight(1);
        tmp = value.modPow(e1, order).multiply(getNqr().modPow(e2, order))
                   .subtract(order);
        if(tmp.equals(BigInteger.ONE.negate()))
          e2 = e2.add(e1tmp);
      }
      
      BigInteger m  = k.subtract(BigInteger.ONE).shiftRight(1);
      value = value.modPow(m.add(BigInteger.ONE), order)
                   .multiply(getNqr().modPow(e2.shiftRight(1), order))
                   .mod(order);
      return this;
    }

    @Override
    public byte[] toByteArray()
    {
      return IntegerUtil.i2bsp(value, order.bitLength());
    }

    @Override
    public boolean isZero()
    {
      return value.signum() == 0;
    }

    @Override
    public boolean isOne()
    {
      return value.compareTo(BigInteger.ONE) == 0;
    }

    @Override
    public boolean equals(Object obj)
    {
      if(obj == this)
        return true;
      
      if((obj == null) || !(obj instanceof FqBigIntegerElement))
        return false;
      
      BigInteger other = ((FqBigIntegerElement) obj).value;
      return value.equals(other);
    }

    @Override
    public FqElement<BigInteger> clone()
    {
      return single_recycler.get(value);
    }

    @Override
    public BigInteger toBigInteger()
    {
      return value;
    }

    @Override
    public FqElement<BigInteger> addNoReductionMutable(FqElement<BigInteger> in)
    {
      value = value.add(in.value);
      return this;
    }

    @Override
    public FqElement<BigInteger> subNoReductionMutable(FqElement<BigInteger> in)
    {
      value = value.subtract(in.value);
      return this;
    }

    @Override
    public FqElement<BigInteger> divByTwo()
    {
      return clone().divByTwoMutable();
    }

    @Override
    public FqElement<BigInteger> divByTwoMutable()
    {
      boolean lsb = value.testBit(0);
      value = value.shiftRight(1);
      if(lsb)
        value = value.add(divTwo);
      
      return this;
    }

    @Override
    public FqElement<BigInteger> divByFour()
    {
      return clone().divByFourMutable();
    }

    @Override
    public FqElement<BigInteger> divByFourMutable()
    {
      boolean lsb = value.testBit(0), nslb = value.testBit(1);
      value = value.shiftRight(2); 
      
      if(nslb)
        value = value.add(divTwo);

      if(lsb)
        value = value.add(divFour);
      
      return this;
    }

    @Override
    public FqElement<BigInteger> addNoReduction(FqElement<BigInteger> element)
    {
      return clone().addNoReductionMutable(element);
    }

    @Override
    public FqElement<BigInteger> subNoReduction(FqElement<BigInteger> element)
    {
      return clone().subNoReductionMutable(element);
    }

    @Override
    public FqElement<BigInteger> twiceNoReduction()
    {
      return addNoReduction(this);
    }

    @Override
    public FqDoubleElement<BigInteger> mulDouble(FqElement<BigInteger> element)
    {
      return double_recycler.get(value.multiply(element.value));
    }

    @Override
    public FqDoubleElement<BigInteger> squareDouble()
    {
      return double_recycler.get(value.multiply(value));
    }

    @Override
    public void recycle()
    {
      single_recycler.put(this);
    }    
  }

  /**
   * Double precision element implementation
   */
  private class FqDoubleBigIntegerElement extends FqDoubleElement<BigInteger>
  {
    public FqDoubleBigIntegerElement(BigInteger value)
    {
      super(value);
    }

    @Override
    public byte[] toByteArray()
    {
      return IntegerUtil.i2bsp(value, order.bitLength() * 2);
    }

    @Override
    public Fq<BigInteger> getField()
    {
      return FqBigInteger.this;
    }

    @Override
    public FqDoubleElement<BigInteger> add(FqDoubleElement<BigInteger> element)
    {
      return clone().addMutable(element);
    }

    /**
     * Adds a {@link BigInteger} to this element. Note that no transformations
     * are done on this {@link BigInteger}.
     * 
     * @param bi The {@link BigInteger} to add
     * 
     * @return A new {@link FqDoubleElement}, representing this + bi
     */
    public FqDoubleElement<BigInteger> add(BigInteger bi)
    {
      return double_recycler.get(value.add(bi));
    }

    @Override
    public FqDoubleElement<BigInteger> clone()
    {
      return double_recycler.get(value);
    }

    @Override
    public FqDoubleElement<BigInteger> addMutable(BigInteger bi)
    {
      value = value.add(bi);
      return this;
    }
    
    @Override
    public FqDoubleElement<BigInteger> sub(FqDoubleElement<BigInteger> element)
    {
      return clone().subMutable(element);
    }
    
    /**
     * Subtraction without the boundary check of {@link #sub(FqDoubleElement)}.
     * 
     * @param element The element to subtract
     * @return A new element, representing this - element
     */
    @Override
    public FqDoubleElement<BigInteger> 
    subNoReductionMutable(FqDoubleElement<BigInteger> element)
    {
      value = value.subtract(element.value);
      return this;
    }

    /**
     * Adds (q << 256) to this and subtracts element from it to avoid underflows.
     * 
     * @param element the Element to subtract from this + (q << 256)
     * 
     * @return A new {@link FqDoubleElement}, representing
     *         this + (q << 256) - element
     */
    public FqDoubleElement<BigInteger> 
    subOpt1(FqDoubleElement<BigInteger> element)
    {
      return add(qn).subMutable(element);
    }

    @Override
    public FqElement<BigInteger> mod()
    {
      return FqBigInteger.this.fromDouble(this);
    }
    
    /**
     * Hands out its internal {@link BigInteger} value.
     * 
     * @return The element's value as {@link BigInteger}
     */
    @Override
    public BigInteger toBigInteger()
    {
      return value;
    }

    @Override
    public FqDoubleElement<BigInteger> twice()
    {
      return add(this);
    }

    @Override
    public boolean isZero()
    {
      return value.signum() == 0;
    }

    @Override
    public boolean isOne()
    {
      return value.equals(BigInteger.ONE);
    }

    @Override
    public FqDoubleElement<BigInteger> twiceMutable()
    {
      return addMutable(this);
    }

    @Override
    public FqDoubleElement<BigInteger>
    addMutable(FqDoubleElement<BigInteger> element)
    {
      value = value.add(element.value);
      return this;
    }

    @Override
    public FqDoubleElement<BigInteger>
    subMutable(FqDoubleElement<BigInteger> element)
    {
      if(value.compareTo(element.value) < 0)
        value = value.add(FqBigInteger.this.getQn());
      
      value = value.subtract(element.value);
      return this;
    }

    @Override
    public boolean equals(Object obj)
    {
      if(obj == this)
        return true;
      
      if((obj == null) || !(obj instanceof FqDoubleBigIntegerElement))
        return false;
      
      BigInteger other = ((FqDoubleBigIntegerElement) obj).value;
      return value.equals(other);
    }

    @Override
    public void recycle()
    {
      double_recycler.put(this);
    }
  }
  
  /** single precision element creator */
  private class SingleCreator
  implements Creator<FqBigIntegerElement, BigInteger>
  {

    @Override
    public FqBigIntegerElement create(BigInteger... values)
    {
      return new FqBigIntegerElement(FqBigInteger.this, values[0]);
    }

    @Override
    public FqBigIntegerElement
    fromObject(FqBigIntegerElement obj, BigInteger... values)
    {
      obj.value = values[0];
      return obj;
    }    
  }
  
  /** double precision element creator */
  private class DoubleCreator
  implements Creator<FqDoubleBigIntegerElement, BigInteger>
  {

    @Override
    public FqDoubleBigIntegerElement create(BigInteger... values)
    {
      return new FqDoubleBigIntegerElement(values[0]);
    }

    @Override
    public FqDoubleBigIntegerElement fromObject(FqDoubleBigIntegerElement obj,
        BigInteger... values)
    {
      obj.value = values[0];
      return obj;
    }    
  }
}
