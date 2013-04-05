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
 * Primitive implementation using {@link BigInteger}. Transforms the input
 * into the montgomery domain. This approach turned out to be significantly
 * slower and is thus not mentioned in the paper.
 * 
 * Incorporates both single- and double precision elements. Does element
 * recycling (fields only, though, as {@link BigInteger}s are mutable).
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class FqMontgomeryBigInteger extends Fq<BigInteger>
{
  private BigInteger divTwo;
  private BigInteger divFour;
  private BigInteger nqr;
  private BigInteger R;
  private BigInteger n0;
  private int rBitLen;
  private BigInteger one;
  private BigInteger two;

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
  public FqMontgomeryBigInteger(Random random, BigInteger order)
  {
    super(random, order);
    
    divTwo  = order.add(BigInteger.ONE).shiftRight(1);
    divFour = divTwo.shiftRight(1);

    qn = order.shiftLeft(order.bitLength());
    R  = BigInteger.ZERO.setBit(256);
    n0 = order.negate().modInverse(R);
    one = R.mod(order);
    two = multiplyMontgomery(BigInteger.valueOf(2), BigInteger.ONE).mod(order);
    rBitLen = R.bitLength();
    nonmontgomery = new FqBigInteger(rnd, order);
    
    single_recycler = new RecycleBin<FqBigIntegerElement, BigInteger>(
                      new FqBigIntegerElement[50], new SingleCreator());
    double_recycler = new RecycleBin<FqDoubleBigIntegerElement, BigInteger>(
                      new FqDoubleBigIntegerElement[20], new DoubleCreator());
  }
  
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
    return single_recycler.get(one);
  }

  @Override
  public FqElement<BigInteger> getZeroElement()
  {
    return single_recycler.get(BigInteger.ZERO);
  }

  @Override
  public FqElement<BigInteger> getTwoElement()
  {
    return single_recycler.get(two);
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
    
    return single_recycler.get(components[0].mod(order).multiply(R).mod(order));
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
    return true;
  }

  @Override
  public Fq<BigInteger> getNonMontgomery()
  {
    return nonmontgomery;
  }

  @Override
  public void recycle(FqElement<BigInteger> element)
  {
    single_recycler.put((FqBigIntegerElement) element);
  }

  @Override
  public FqElement<BigInteger> fromDouble(FqDoubleElement<BigInteger> dbl)
  {
    return new FqBigIntegerElement(dbl.value);
  }

  @Override
  public Fq<BigInteger> getNew(BigInteger modulus)
  {
    return new FqMontgomeryBigInteger(rnd, modulus);
  }

  @Override
  public Fq<BigInteger> getNonMontgomery(BigInteger modulus)
  {
    return new FqBigInteger(rnd, modulus);
  }
  
  private BigInteger multiplyMontgomery(BigInteger a, BigInteger b)
  {
    BigInteger t = a.multiply(b);
    
    /* mod() R is actually a truncation of i2 to R-1's bitlength, since
     * R is 2^256.
     * 
     * Several methods were tried, but interestingly enough, mod() was the
     * fastest.
     */
    BigInteger i2 = t.multiply(n0);
    i2 = i2.mod(R);
    BigInteger i3 = i2.multiply(order).add(t);
    i3 = i3.shiftRight(rBitLen - 1);
    if(i3.compareTo(order) > 0)
      i3 = i3.subtract(order);

    return i3;    
  }
  
  private class FqBigIntegerElement extends FqElement<BigInteger>
  {

    private FqBigIntegerElement(Fq<BigInteger> target_field,
                                BigInteger value, boolean transform)
    {
      super(target_field, transform ? value.multiply(R).mod(order) : value);
    }
    
    private FqBigIntegerElement(BigInteger value)
    {
      super(FqMontgomeryBigInteger.this, value);
      this.value = multiplyMontgomery(this.value, BigInteger.ONE).mod(order);
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
      value = multiplyMontgomery(value, element.value);
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
      value = value.multiply(bi);
      return this;
    }

    @Override
    public FqElement<BigInteger> pow(BigInteger exp)
    {
      BigInteger out = R;
      for(int i = exp.bitLength() - 1; i >= 0; i--)
      {
        out = multiplyMontgomery(out, out);
        if(exp.testBit(i))
          out = multiplyMontgomery(out, value);
      }
      
      return single_recycler.get(out);
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
      // montgomery inversion    
      BigInteger modulus = order;
      BigInteger u = modulus, v = value, r = BigInteger.ZERO, s = BigInteger.ONE;
      int k = 0;
      while(v.signum() > 0)
      {
        if(!u.testBit(0)) {
          u = u.shiftRight(1);
          s = s.shiftLeft(1);
        }
        else if(!v.testBit(0))
        {
          v = v.shiftRight(1);
          r = r.shiftLeft(1);
        }
        else if(v.compareTo(u) >= 0)
        {
          v = v.subtract(u);
          s = s.add(r);
          v = v.shiftRight(1);
          r = r.shiftLeft(1);
        }
        else
        {
          u = u.subtract(v);
          r = r.add(s);
          u = u.shiftRight(1);
          s = s.shiftLeft(1);
        }
        k++;
      }
      if(r.compareTo(modulus) >= 0)
        r = r.subtract(modulus);
      
      r = modulus.subtract(r);    
      value = r.multiply(BigInteger.ZERO.setBit(512-k)).mod(modulus);
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
      // there might be more efficient ways, but sqrt() is non-critical..
      value = multiplyMontgomery(value, BigInteger.ONE).mod(order);
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
      value = value.modPow(m.add(BigInteger.ONE), order).multiply(getNqr()
                   .modPow(e2.shiftRight(1), order)).mod(order);
      value = value.multiply(R).mod(order);
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
      return value.compareTo(R) == 0;
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
    public String toString(int radix)
    {
      return value.toString(radix) + " [mont]";
    }

    @Override
    public void recycle()
    {
      single_recycler.put(this);
    }
    
  }
  
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
      return FqMontgomeryBigInteger.this;
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
      return clone().addMutable(bi);
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
     * Adds (q << 256) to this and subtracts element from it to avoid
     * underflows.
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
      return FqMontgomeryBigInteger.this.fromDouble(this);
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
    public String toString(int radix)
    {
      return super.toString(radix) + " [mont]";
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
      return value.equals(R);
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
        value = value.add(FqMontgomeryBigInteger.this.getQn());
      
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
  
  private class SingleCreator
  implements Creator<FqBigIntegerElement, BigInteger>
  {

    @Override
    public FqBigIntegerElement create(BigInteger... values)
    {
      return new FqBigIntegerElement(FqMontgomeryBigInteger.this, values[0], false);
    }

    @Override
    public FqBigIntegerElement
    fromObject(FqBigIntegerElement obj, BigInteger... values)
    {
      obj.value = values[0];
      return obj;
    }    
  }
}
