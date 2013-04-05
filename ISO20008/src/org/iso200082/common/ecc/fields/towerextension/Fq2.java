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

package org.iso200082.common.ecc.fields.towerextension;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq2DoubleElement;
import org.iso200082.common.ecc.elements.doubleprecision.FqDoubleElement;
import org.iso200082.common.util.Creator;
import org.iso200082.common.util.RecycleBin;

/**
 * Represents the tower extension field F(q^2).
 * 
 * See {@link Field} for interface-level descriptions and
 * {@link TowerExtensionField} for other overridden method descriptions.
 * 
 * @see Field
 * @see TowerExtensionField
 * @see Fq2Element
 * 
 * @param <P> The primitive Type to use
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq2
<
  P
>
extends TowerExtensionField<Fq2Element<P>, FqElement<P>, Fq2<P>, Fq<P>>
{

  /** recycler for single-precision Fq2 elements */
  private RecycleBin<Fq2Element<P>, FqElement<P>> single_recycler;
  
  /** recycle for double-precision Fq2 elements */
  private RecycleBin<Fq2DoubleElement<P>, FqDoubleElement<P>> double_recycler;
  
  /**
   * Ctor, sets the irreducible coefficient that was used to create the field
   * 
   * (e.g. if F(q^2) = F(q)[u](u^2 - beta), then beta is the irreducible
   * polynomial coefficient)
   * 
   * @param random A {@link Random} instance
   * @param irreduciblePolyCoefficient The beta coefficient
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public Fq2(Random random, FqElement<P> irreduciblePolyCoefficient)
  {
    super(random, irreduciblePolyCoefficient);
    single_recycler = 
      new RecycleBin<Fq2Element<P>, FqElement<P>>(
          new Fq2Element[20], new SingleCreator());
    
    double_recycler = 
      new RecycleBin<Fq2DoubleElement<P>, FqDoubleElement<P>>(
          new Fq2DoubleElement[10], new DoubleCreator());
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getRandomElement()
  {
    return single_recycler.get(getBaseField().getRandomElement(),
                               getBaseField().getRandomElement());
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getOneElement()
  {
    return single_recycler.get(getBaseField().getOneElement(),
                               getBaseField().getZeroElement());
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getZeroElement()
  {
    return single_recycler.get(getBaseField().getZeroElement(),
                               getBaseField().getZeroElement());
  }

  @Override
  public BigInteger getOrder()
  {
    return irreducible.getField().getOrder().pow(2);
  }

  @Override
  public int getNumberOfCoefficients()
  {
    return 2;
  }

  @Override
  public int getTotalNumberOfCoefficients()
  {
    return getBaseField().getTotalNumberOfCoefficients() *
           getNumberOfCoefficients();
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElementFromByteArray(byte[] data)
  {
    // assumes that all components are of same length
    // (being math.ceil(q.bitlen/8))
    
    if(data.length % getTotalNumberOfCoefficients() != 0)
      throw new IllegalArgumentException("Malformed byte array");
    
    int len = data.length, half = len / getNumberOfCoefficients();
    return single_recycler.get(getBaseField().getElementFromByteArray(
                 Arrays.copyOfRange(data, 0, half)),
               getBaseField().getElementFromByteArray(
                 Arrays.copyOfRange(data, half, len))
               );
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElementFromComponents(BigInteger... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();

    return single_recycler.get(getBaseField().getElementFromComponents(
                 Arrays.copyOfRange(components, 0, half)),
               getBaseField().getElementFromComponents(
                 Arrays.copyOfRange(components, half, len))
               );
  }
  
  /**
   * Returns a new Fq2 element from the two Fq components a, b.
   * 
   * @param a Component a
   * @param b Component b
   * 
   * @return The "merged" Fq2 element
   */
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElement(FqElement<P> a, FqElement<P> b)
  {
    return single_recycler.get(a, b);
  }
  
  /**
   * Returns a new double-precision Fq2 element from the two Fq components a, b.
   * 
   * @param a Component a
   * @param b Component b
   * 
   * @return The "merged" Fq2 double-precision element
   */
  @SuppressWarnings("unchecked")
  public Fq2DoubleElement<P> getDoubleElement(FqDoubleElement<P> a, FqDoubleElement<P> b)
  {
    return double_recycler.get(a, b);
  }
    
  /**
   * Returns the given double-precision element back to the pool of available
   * instances.
   * 
   * @param element The element to recycle
   */
  public void recycle(Fq2DoubleElement<P> element)
  {
    double_recycler.put(element);
  }
  
  /**
   * Returns the given single-precision element back to the pool of available
   * instance
   * 
   * @param element The element to recycle
   */
  public void recycle(Fq2Element<P> element)
  {
    single_recycler.put(element);
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElementFromComponents(long... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();
    
    return single_recycler.get(
               getBaseField().getElementFromComponents(
                 Arrays.copyOfRange(components, 0, half)),
               getBaseField().getElementFromComponents(
                 Arrays.copyOfRange(components, half, len))
               );
  }

  @Override
  public Fq2Element<P> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElementFromComponents(int radix, String... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, half = len / getNumberOfCoefficients();
    
    return single_recycler.get(
               getBaseField().getElementFromComponents(radix,
                 Arrays.copyOfRange(components, 0, half)),
               getBaseField().getElementFromComponents(radix,
                 Arrays.copyOfRange(components, half, len))
               );
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq2Element<P> getElementFromComponents(FqElement<P>... elements)
  {
    if(elements.length != getNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    return single_recycler.get(elements[0], elements[1]);
  }

  private class SingleCreator 
  implements Creator<Fq2Element<P>, FqElement<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq2Element<P> create(FqElement<P>... values)
    {
      return new Fq2Element<P>(Fq2.this, values[0], values[1]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq2Element<P> fromObject(Fq2Element<P> obj, FqElement<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      return obj;
    }
    
  }

  private class DoubleCreator 
  implements Creator<Fq2DoubleElement<P>, FqDoubleElement<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq2DoubleElement<P> create(FqDoubleElement<P>... values)
    {
      return new Fq2DoubleElement<P>(Fq2.this, values[0], values[1]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq2DoubleElement<P> fromObject(Fq2DoubleElement<P> obj, FqDoubleElement<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      return obj;
    }
    
  }

}
