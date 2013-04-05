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
import org.iso200082.common.ecc.elements.Fq6Element;
import org.iso200082.common.ecc.elements.doubleprecision.Fq2DoubleElement;
import org.iso200082.common.ecc.elements.doubleprecision.Fq6DoubleElement;
import org.iso200082.common.util.Creator;
import org.iso200082.common.util.RecycleBin;


/**
 * Represents the tower extension field F(q^6).
 * 
 * See {@link Field} for interface-level descriptions and
 * {@link TowerExtensionField} for other overridden method descriptions.
 * 
 * @see Field
 * @see TowerExtensionField
 * @see Fq6Element
 * 
 * @param <P> The primitive Type to use
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Fq6<P>
extends TowerExtensionField<Fq6Element<P>, Fq2Element<P>, Fq6<P>, Fq2<P>>
{
  /** recycler for single-precision Fq6 elements */
  private RecycleBin<Fq6Element<P>, Fq2Element<P>> single_recycler;

  /** recycler for double-precision Fq6 elements */
  private RecycleBin<Fq6DoubleElement<P>, Fq2DoubleElement<P>> double_recycler;
  
  /**
   * Ctor, sets the irreducible coefficient that was used to create the field
   * 
   * (e.g. if F(q^6) = F(q^2)[v](v^3 - xi), then xi is the irreducible
   * polynomial coefficient)
   * 
   * @param random A {@link Random} instance
   * @param irreduciblePolyCoefficient The xi coefficient
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public Fq6(Random random, Fq2Element<P> irreduciblePolyCoefficient)
  {
    super(random, irreduciblePolyCoefficient);
    single_recycler = new RecycleBin<Fq6Element<P>, Fq2Element<P>>(
                      new Fq6Element[20], new SingleCreator());
    double_recycler = new RecycleBin<Fq6DoubleElement<P>, Fq2DoubleElement<P>>(
                      new Fq6DoubleElement[10], new DoubleCreator());
  }

  @Override
  public Fq6Element<P> getRandomElement()
  {
    return getElement(getBaseField().getRandomElement(),
                      getBaseField().getRandomElement(),
                      getBaseField().getRandomElement());
  }

  @Override
  public Fq6Element<P> getOneElement()
  {
    return getElement(getBaseField().getOneElement(),
                      getBaseField().getZeroElement(),
                      getBaseField().getZeroElement());
  }

  @Override
  public Fq6Element<P> getZeroElement()
  {
    return getElement(getBaseField().getZeroElement(),
                      getBaseField().getZeroElement(),
                      getBaseField().getZeroElement());
  }

  @Override
  public BigInteger getOrder()
  {
    return irreducible.getField().getOrder().pow(3);
  }

  @Override
  public int getNumberOfCoefficients()
  {
    return 3;
  }

  @Override
  public int getTotalNumberOfCoefficients()
  {
    return getBaseField().getTotalNumberOfCoefficients() * 
           getNumberOfCoefficients();
  }

  @Override
  public Fq6Element<P> getElementFromByteArray(byte[] data)
  {
    // assumes that all components are of same length
    // (being math.ceil(q.bitlen/8))
    
    if(data.length % getTotalNumberOfCoefficients() != 0)
      throw new IllegalArgumentException("Malformed byte array");
    
    int len = data.length, third = len / getNumberOfCoefficients();
    return getElement(getBaseField().getElementFromByteArray(
                        Arrays.copyOfRange(data, 0, third)),
                      getBaseField().getElementFromByteArray(
                        Arrays.copyOfRange(data, third, 2*third)),
                      getBaseField().getElementFromByteArray(
                        Arrays.copyOfRange(data, 2*third, len))
                      );
  }

  @Override
  public Fq6Element<P> getElementFromComponents(BigInteger... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, third = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 0, third)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, third, 2*third)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 2*third, len))
                      );
  }

  @Override
  public Fq6Element<P> getElementFromComponents(long... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, third = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 0, third)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, third, 2*third)),
                      getBaseField().getElementFromComponents(
                        Arrays.copyOfRange(components, 2*third, len))
                      );
  }

  @Override
  public Fq6Element<P> getElementFromComponents(String... components)
  {
    return getElementFromComponents(10, components);
  }

  @Override
  public Fq6Element<P> getElementFromComponents(int radix, String... components)
  {
    if(components.length != getTotalNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    int len = components.length, third = len / getNumberOfCoefficients();
    
    return getElement(getBaseField().getElementFromComponents(radix,
                        Arrays.copyOfRange(components, 0, third)),
                      getBaseField().getElementFromComponents(radix,
                        Arrays.copyOfRange(components, third, 2*third)),
                      getBaseField().getElementFromComponents(radix,
                        Arrays.copyOfRange(components, 2*third, len))
                      );
  }

  @Override
  @SuppressWarnings("unchecked")
  public Fq6Element<P> getElementFromComponents(Fq2Element<P>... elements)
  {
    if(elements.length != getNumberOfCoefficients())
      throw new IllegalArgumentException("invalid number of components");
    
    return getElement(elements[0], elements[1], elements[2]);
  }
  
  /**
   * Returns a new Fq6 element from the three Fq2 components a, b and c.
   * 
   * @param a Component a
   * @param b Component b
   * @param c Component c
   * 
   * @return The "merged" Fq6 element
   */
  @SuppressWarnings("unchecked")
  public Fq6Element<P> getElement(Fq2Element<P> a, Fq2Element<P> b, 
                                  Fq2Element<P> c)
  {
    return single_recycler.get(a, b, c);
  }


  /**
   * Returns a new double-precision Fq6 element from the three double-precision 
   * Fq2 components a, b and c.
   * 
   * @param a Component a
   * @param b Component b
   * @param c Component c
   * 
   * @return The "merged" double-precision Fq6 element
   */
  @SuppressWarnings("unchecked")
  public Fq6DoubleElement<P> getDoubleElement(Fq2DoubleElement<P> a, 
                                              Fq2DoubleElement<P> b, 
                                              Fq2DoubleElement<P> c)
  {
    return double_recycler.get(a, b, c);
  }

  /**
   * Returns a given element to the pool of available ones
   * 
   * @param element The element to recycle
   */
  public void recycle(Fq6DoubleElement<P> element)
  {
    double_recycler.put(element);
  }
  
  @Override
  public void recycle(Fq6Element<P> element)
  {
    single_recycler.put(element);
  }

  private class SingleCreator
  implements Creator<Fq6Element<P>, Fq2Element<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq6Element<P> create(Fq2Element<P>... values)
    {
      return new Fq6Element<P>(Fq6.this, values[0], values[1], values[2]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq6Element<P> fromObject(Fq6Element<P> obj, Fq2Element<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      obj.c = values[2];
      return obj;
    }    
  }

  private class DoubleCreator
  implements Creator<Fq6DoubleElement<P>, Fq2DoubleElement<P>>
  {

    @Override
    @SuppressWarnings("unchecked")
    public Fq6DoubleElement<P> create(Fq2DoubleElement<P>... values)
    {
      return new Fq6DoubleElement<P>(Fq6.this, values[0], values[1], values[2]);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Fq6DoubleElement<P> 
    fromObject(Fq6DoubleElement<P> obj, Fq2DoubleElement<P>... values)
    {
      obj.a = values[0];
      obj.b = values[1];
      obj.c = values[2];
      return obj;
    }    
  }

}
