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

package org.iso200082.common.api;

import org.iso200082.common.api.exceptions.SchemeException;

/**
 * Selection helper that statically loads a scheme from an ID string,
 * internally using the {@link SchemeFactory}.
 * 
 * Note that the environment property "sig-scheme-impl" needs to be set to
 * the concrete factory implementation for this to work (in theory, one could
 * exchange the implementation by a custom one).
 * 
 * For using the shipped code, add
 * -Dsig-scheme-impl=org.iso200082.common.ISO20008Factory
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see GroupSignatureScheme
 * @see SchemeFactory
 */
public abstract class SchemeSelector
{
  /** Factory instance */
  private static SchemeFactory instance = null;
  
  /** loads the factory instance (if not already done so) */
  private static void getInstance()
  throws ClassNotFoundException, InstantiationException, IllegalAccessException
  {
    String impl = System.getProperty("sig-scheme-impl");
    Class<?> sigfactory = Class.forName(impl);
    instance = (SchemeFactory) sigfactory.newInstance();
  }
  
  /**
   * Loads a scheme, encapsulating all the hassle of instantiating a scheme
   * factory.
   * 
   * @param kind The ID of the scheme
   * @return a new {@link GroupSignatureScheme} instance
   * 
   * @throws SchemeException if there is no such scheme
   */
  public static GroupSignatureScheme load(String kind) throws SchemeException
  {
    if(instance == null)
    {
      try {
        getInstance();
      } catch(Exception e) {
        throw new SchemeException("Could not load Scheme: " + kind);
      }
    }
      
    return instance.loadScheme(kind);
  }
}
