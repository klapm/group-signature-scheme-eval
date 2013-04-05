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


import java.util.Set;

import org.iso200082.common.api.exceptions.SchemeException;


/**
 * Simple factory to construct a {@link GroupSignatureScheme} object from
 * and identifier string (kind).
 * 
 * See ISO20008Factory for an implementation example.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see GroupSignatureScheme
 * @see SchemeSelector
 */
public abstract class SchemeFactory
{
  /**
   * Creates a {@link GroupSignatureScheme} instance from the given ID (kind).
   * 
   * @param kind The mechanism ID.
   * 
   * @return a scheme instance
   * 
   * @throws SchemeException if there is no such scheme
   */
  public abstract GroupSignatureScheme loadScheme(String kind)
  throws SchemeException;
  
  /**
   * Returns a list of supported schemes
   * 
   * @return a list of scheme identifiers known by this factory
   */
  public abstract Set<String> getSupportedSchemes();
}
